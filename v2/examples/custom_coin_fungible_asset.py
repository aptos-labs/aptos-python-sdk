"""Example: Coin API vs Fungible Asset API — side-by-side comparison.

Aptos has two systems for token balances and transfers:

1. **Coin module** (0x1::coin) — the original API. Uses Move generics:
   `CoinStore<0x1::aptos_coin::AptosCoin>`. Works with APT and custom coins.

2. **Fungible Asset module** (0x1::primary_fungible_store) — the newer standard.
   Uses a metadata object address instead of generics. APT's FA metadata address
   is 0xa. All new tokens should prefer the FA standard.

Both systems work for APT — this example shows them side-by-side.
"""

import asyncio

from aptos_sdk_v2 import Account, Aptos, AptosConfig, Network
from aptos_sdk_v2.types import AccountAddress

# APT's fungible asset metadata object address.
# This is a well-known special address (0xa) on all Aptos networks.
APT_FA_ADDRESS = AccountAddress.from_str("0xa")


async def main():
    config = AptosConfig(network=Network.DEVNET)
    async with Aptos(config) as aptos:
        # Create and fund accounts
        alice = Account.generate()
        bob = Account.generate()
        print(f"Alice: {alice.address}")
        print(f"Bob:   {bob.address}")

        print("\nFunding accounts...")
        await asyncio.gather(
            aptos.faucet.fund_account(alice.address, 100_000_000),
            aptos.faucet.fund_account(bob.address, 10_000_000),
        )

        # ── Query balances using both APIs ──────────────────────────────
        print("\n── Balance Comparison ──")

        # Coin API: uses the 0x1::coin::balance view function with a type argument
        coin_balance = await aptos.coin.balance(alice.address)
        print(f"Alice via Coin API:           {coin_balance}")

        # Fungible Asset API: uses 0x1::primary_fungible_store::balance
        # with the FA metadata object address instead of a type argument
        fa_balance = await aptos.fungible_asset.balance(alice.address, APT_FA_ADDRESS)
        print(f"Alice via Fungible Asset API: {fa_balance}")

        # Both should agree for APT
        print(f"Balances match: {coin_balance == fa_balance}")

        # ── Transfer using Coin API ─────────────────────────────────────
        print("\n── Coin API Transfer ──")
        print("Transferring 5000 octas via Coin API...")
        txn_hash = await aptos.coin.transfer(alice, bob.address, 5_000)
        result = await aptos.transaction.wait_for_transaction(txn_hash)
        print(f"Transaction: {txn_hash}")
        print(f"Success: {result['success']}")

        bob_balance = await aptos.coin.balance(bob.address)
        print(f"Bob balance after Coin transfer: {bob_balance}")

        # ── Transfer using Fungible Asset API ───────────────────────────
        print("\n── Fungible Asset API Transfer ──")
        print("Transferring 3000 octas via FA API...")

        # fa_address is the metadata object address of the fungible asset.
        # For APT, this is always 0xa. For a custom FA, it would be the
        # address of the metadata object created when the FA was initialized.
        txn_hash = await aptos.fungible_asset.transfer(
            alice, APT_FA_ADDRESS, bob.address, 3_000
        )
        result = await aptos.transaction.wait_for_transaction(txn_hash)
        print(f"Transaction: {txn_hash}")
        print(f"Success: {result['success']}")

        bob_balance = await aptos.fungible_asset.balance(bob.address, APT_FA_ADDRESS)
        print(f"Bob balance after FA transfer: {bob_balance}")

        # ── Final balances via both APIs ────────────────────────────────
        print("\n── Final Balances ──")
        alice_coin = await aptos.coin.balance(alice.address)
        alice_fa = await aptos.fungible_asset.balance(alice.address, APT_FA_ADDRESS)
        bob_coin = await aptos.coin.balance(bob.address)
        bob_fa = await aptos.fungible_asset.balance(bob.address, APT_FA_ADDRESS)

        print(f"Alice — Coin: {alice_coin}, FA: {alice_fa}, match: {alice_coin == alice_fa}")
        print(f"Bob   — Coin: {bob_coin}, FA: {bob_fa}, match: {bob_coin == bob_fa}")

        # ── Custom coin type (Coin API only) ────────────────────────────
        # To query a non-APT coin, pass the coin_type parameter:
        #
        #   balance = await aptos.coin.balance(
        #       alice.address,
        #       coin_type="0xDEPLOYER::module_name::MyCoin",
        #   )
        #
        #   txn_hash = await aptos.coin.transfer(
        #       alice, bob.address, 1_000,
        #       coin_type="0xDEPLOYER::module_name::MyCoin",
        #   )
        #
        # For custom fungible assets (FA API), use the metadata object address:
        #
        #   custom_fa = AccountAddress.from_str("0x<metadata_object_address>")
        #   balance = await aptos.fungible_asset.balance(alice.address, custom_fa)


if __name__ == "__main__":
    asyncio.run(main())
