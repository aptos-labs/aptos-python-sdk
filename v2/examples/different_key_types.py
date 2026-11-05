"""Example: Create accounts with different key types.

Demonstrates Ed25519, Secp256k1, and SLH-DSA-SHA2-128s (post-quantum,
AIP-137) accounts signing and submitting transactions identically.
SLH-DSA signing requires ``pip install "aptos-sdk-v2[slh-dsa-sha2-128s]"``
and a network whose on-chain crypto supports the scheme.
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

        # Generate an SLH-DSA-SHA2-128s (post-quantum) account
        alice_slh = Account.generate_slh_dsa_sha2_128s()
        print(f"\nAlice (SLH-DSA-SHA2-128s): {alice_slh.address}")
        print(f"  Public key type: {type(alice_slh.public_key).__name__}")

        # Create a recipient
        bob = Account.generate()
        print(f"\nBob:               {bob.address}")

        # Fund all accounts
        print("\nFunding accounts...")
        await asyncio.gather(
            aptos.faucet.fund_account(alice_ed25519.address, 100_000_000),
            aptos.faucet.fund_account(alice_secp256k1.address, 100_000_000),
            aptos.faucet.fund_account(alice_slh.address, 100_000_000),
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

        # Transfer from SLH-DSA-SHA2-128s account
        print("\nTransferring 1000 octas from SLH-DSA-SHA2-128s account to Bob...")
        txn_hash = await aptos.coin.transfer(alice_slh, bob.address, 1_000)
        result = await aptos.transaction.wait_for_transaction(txn_hash)
        print(f"  Transaction: {txn_hash}")
        print(f"  Success: {result['success']}")

        # Check final balances
        bob_balance = await aptos.coin.balance(bob.address)
        print(f"\nBob final balance: {bob_balance}")


if __name__ == "__main__":
    asyncio.run(main())
