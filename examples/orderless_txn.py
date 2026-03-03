"""
Complete examples for orderless transactions in Aptos Python SDK.

Demonstrates:
1. Regular orderless transaction with EntryFunction
2. Orderless transaction with Script
3. Multisig orderless transaction with execution
4. Multisig voting-only transaction (no execution)
"""

import asyncio
import time

from aptos_sdk.account import Account
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.async_client import ClientConfig, FaucetClient, RestClient
from aptos_sdk.bcs import Serializer
from aptos_sdk.transactions import (
    EntryFunction,
    Script,
    TransactionArgument,
    TransactionPayload,
)

from .common import API_KEY, FAUCET_URL, NODE_URL


async def example_regular_orderless():
    """Example 1: Regular orderless transaction with EntryFunction"""
    print("Example 1: Regular Orderless Transaction (EntryFunction)")

    sender = Account.generate()
    recipient = Account.generate()

    print(f"Sender: {sender.address()}")
    print(f"Recipient: {recipient.address()}")

    print("\nFunding sender...")
    await faucet_client.fund_account(sender.address(), 100_000_000)

    # Create transfer payload
    payload = TransactionPayload(
        EntryFunction.natural(
            "0x1::aptos_account",
            "transfer",
            [],
            [
                TransactionArgument(recipient.address(), Serializer.struct),
                TransactionArgument(1_000_000, Serializer.u64),
            ],
        )
    )

    # Use timestamp-based nonce for uniqueness
    nonce = int(time.time() * 1000)

    print(f"Submitting orderless transaction with nonce: {nonce}...")
    tx_hash = await client.submit_orderless_transaction(
        sender, payload, nonce=nonce, wait=True
    )

    print(f"✓ Transaction completed: {tx_hash}")

    balance = await client.account_balance(recipient.address())
    print(f"✓ Recipient balance: {balance} octas")


async def example_script_orderless():
    """Example 2: Orderless transaction with Script"""
    print("Example 2: Orderless Transaction with Script")

    sender = Account.generate()

    print(f"Sender: {sender.address()}")

    print("\nFunding sender...")
    await faucet_client.fund_account(sender.address(), 100_000_000)

    # Create a script payload (example with empty bytecode - replace with actual script)
    # In practice, you'd compile a Move script and use the bytecode
    script = Script(
        code=b"", ty_args=[], args=[]  # Your compiled Move script bytecode here
    )

    payload = TransactionPayload(script)
    nonce = int(time.time() * 1000)

    print(f"Submitting orderless script transaction with nonce: {nonce}...")

    # Note: This will fail without actual valid script bytecode
    # This is just to show the API usage
    try:
        tx_hash = await client.submit_orderless_transaction(
            sender, payload, nonce=nonce, wait=True
        )
        print(f"✓ Transaction completed: {tx_hash}")
    except Exception as e:
        print(f"Note: Script example failed (expected without valid bytecode): {e}")


async def example_multisig_orderless_with_execution():
    """Example 3: Multisig orderless transaction with execution"""
    print("Example 3: Multisig Orderless Transaction with Execution")

    # Create multisig participants
    owner1 = Account.generate()
    owner2 = Account.generate()
    recipient = Account.generate()

    print(f"Owner 1: {owner1.address()}")
    print(f"Owner 2: {owner2.address()}")
    print(f"Recipient: {recipient.address()}")

    print("\nFunding owner 1...")
    await faucet_client.fund_account(owner1.address(), 100_000_000)

    # In practice, you would:
    # 1. Create the multisig account first
    # 2. Get the multisig account address
    # For this example, we'll use a placeholder address
    multisig_address = AccountAddress.from_str(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    )

    print(f"\nMultisig Address (example): {multisig_address}")

    # Create transfer payload for multisig execution
    payload = TransactionPayload(
        EntryFunction.natural(
            "0x1::aptos_account",
            "transfer",
            [],
            [
                TransactionArgument(recipient.address(), Serializer.struct),
                TransactionArgument(500_000, Serializer.u64),
            ],
        )
    )

    nonce = int(time.time() * 1000)

    print(f"\nSubmitting multisig orderless transaction with nonce: {nonce}...")

    try:
        tx_hash = await client.submit_orderless_transaction(
            owner1, payload, nonce=nonce, multisig_address=multisig_address, wait=True
        )
        print(f"✓ Transaction completed: {tx_hash}")
    except Exception as e:
        print(
            f"Note: Multisig example failed (expected without actual multisig setup): {e}"
        )


async def example_replay_protection():
    """Example 5: Demonstrating replay protection with same nonce"""
    print("Example 5: Replay Protection (Same Nonce)")

    sender = Account.generate()
    recipient = Account.generate()

    print(f"Sender: {sender.address()}")
    print(f"Recipient: {recipient.address()}")

    print("\nFunding sender...")
    await faucet_client.fund_account(sender.address(), 100_000_000)

    # Create transfer payload
    payload = TransactionPayload(
        EntryFunction.natural(
            "0x1::aptos_account",
            "transfer",
            [],
            [
                TransactionArgument(recipient.address(), Serializer.struct),
                TransactionArgument(1_000_000, Serializer.u64),
            ],
        )
    )

    # Use fixed nonce for both transactions
    nonce = 999999

    print(f"\nSubmitting first transaction with nonce: {nonce}...")
    tx1_hash = await client.submit_orderless_transaction(
        sender, payload, nonce=nonce, wait=True
    )
    print(f"✓ First transaction completed: {tx1_hash}")

    print(f"\nAttempting second transaction with SAME nonce: {nonce}...")
    try:
        tx2_hash = await client.submit_orderless_transaction(
            sender, payload, nonce=nonce, wait=True
        )
        print(f"⚠ Second transaction succeeded (unexpected): {tx2_hash}")
        print("This might mean the first transaction wasn't fully indexed yet")
    except Exception as e:
        print(f"✓ Replay protection worked! Transaction rejected: {e}")
        print(f"  Error: {e}")


async def main():
    """Run all examples"""
    print("APTOS ORDERLESS TRANSACTIONS - COMPLETE EXAMPLES")

    try:
        # Example 1: Regular orderless transaction
        await example_regular_orderless()

        # Example 2: Script orderless (will fail without valid bytecode)
        await example_script_orderless()

        # Example 3: Multisig with execution (requires multisig setup)
        await example_multisig_orderless_with_execution()

        # Example 5: Replay protection demonstration
        await example_replay_protection()

        await client.close()
        await faucet_client.close()

        print("ALL EXAMPLES COMPLETED")

    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    client = RestClient(NODE_URL, client_config=ClientConfig(api_key=API_KEY))
    faucet_client = FaucetClient(FAUCET_URL, client)
    asyncio.run(main())
