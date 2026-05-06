"""Example: Create accounts with different key types (Ed25519 vs Secp256k1).

Demonstrates that both key types can sign and submit transactions identically.
"""

import asyncio

from aptos_sdk_v2 import Account, Aptos, AptosConfig, Network


async def main():
    config = AptosConfig(network=Network.DEVNET)
    async with Aptos(config) as aptos:
        # Generate an Ed25519 account (default)
        alice_ed25519 = Account.generate()
        print(f"Alice (Ed25519):   {alice_ed25519.address}")
        print(f"  Public key type: {type(alice_ed25519.public_key).__name__}")

        # Generate a Secp256k1 account
        alice_secp256k1 = Account.generate_secp256k1()
        print(f"\nAlice (Secp256k1): {alice_secp256k1.address}")
        print(f"  Public key type: {type(alice_secp256k1.public_key).__name__}")

        # Create a recipient
        bob = Account.generate()
        print(f"\nBob:               {bob.address}")

        # Fund all accounts
        print("\nFunding accounts...")
        await asyncio.gather(
            aptos.faucet.fund_account(alice_ed25519.address, 100_000_000),
            aptos.faucet.fund_account(alice_secp256k1.address, 100_000_000),
            aptos.faucet.fund_account(bob.address, 10_000_000),
        )

        # Transfer from Ed25519 account
        print("\nTransferring 1000 octas from Ed25519 account to Bob...")
        txn_hash = await aptos.coin.transfer(alice_ed25519, bob.address, 1_000)
        result = await aptos.transaction.wait_for_transaction(txn_hash)
        print(f"  Transaction: {txn_hash}")
        print(f"  Success: {result['success']}")

        # Transfer from Secp256k1 account
        print("\nTransferring 1000 octas from Secp256k1 account to Bob...")
        txn_hash = await aptos.coin.transfer(alice_secp256k1, bob.address, 1_000)
        result = await aptos.transaction.wait_for_transaction(txn_hash)
        print(f"  Transaction: {txn_hash}")
        print(f"  Success: {result['success']}")

        # Check final balances
        bob_balance = await aptos.coin.balance(bob.address)
        print(f"\nBob final balance: {bob_balance}")


if __name__ == "__main__":
    asyncio.run(main())
