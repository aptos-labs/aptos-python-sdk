"""Example: Fetch various on-chain data using the SDK.

Demonstrates ledger info, block queries, account info, resources,
balances, and view functions.
"""

import asyncio
import json

from aptos_sdk_v2 import Account, Aptos, AptosConfig, Network


async def main():
    config = AptosConfig(network=Network.DEVNET)
    async with Aptos(config) as aptos:
        # --- Ledger info ---
        print("=== Ledger Info ===")
        info = await aptos.general.get_ledger_info()
        print(f"Chain ID:       {info['chain_id']}")
        print(f"Epoch:          {info['epoch']}")
        print(f"Ledger version: {info['ledger_version']}")
        print(f"Block height:   {info['block_height']}")

        # --- Chain ID (convenience) ---
        chain_id = await aptos.general.get_chain_id()
        print(f"\nChain ID (direct): {chain_id}")

        # --- Block by height ---
        print("\n=== Block at Height 1 ===")
        block = await aptos.general.get_block_by_height(1)
        print(f"Block hash:     {block['block_hash']}")
        print(f"Block height:   {block['block_height']}")
        print(f"Timestamp:      {block['block_timestamp']}")

        # --- Account info ---
        alice = Account.generate()
        print(f"\n=== Account Info ===")
        print(f"Address: {alice.address}")

        print("\nFunding account...")
        await aptos.faucet.fund_account(alice.address, 100_000_000)

        account_info = await aptos.account.get_info(alice.address)
        print(f"Sequence number:    {account_info['sequence_number']}")
        print(f"Authentication key: {account_info['authentication_key']}")

        # --- Account resources ---
        print("\n=== Account Resources ===")
        resources = await aptos.account.get_resources(alice.address)
        print(f"Total resources: {len(resources)}")
        for r in resources[:5]:  # Show first 5
            print(f"  - {r['type']}")
        if len(resources) > 5:
            print(f"  ... and {len(resources) - 5} more")

        # --- Balance via REST API ---
        print("\n=== Balance (REST API) ===")
        balance_rest = await aptos.account.get_balance(alice.address)
        print(f"APT balance (REST): {balance_rest}")

        # --- Balance via view function (CoinApi) ---
        print("\n=== Balance (View Function via CoinApi) ===")
        balance_view = await aptos.coin.balance(alice.address)
        print(f"APT balance (view): {balance_view}")

        # --- Raw view function call ---
        print("\n=== Raw View Function ===")
        result = await aptos.general.view(
            "0x1::coin",
            "balance",
            ["0x1::aptos_coin::AptosCoin"],
            [str(alice.address)],
        )
        print(f"View result: {json.dumps(result)}")


if __name__ == "__main__":
    asyncio.run(main())
