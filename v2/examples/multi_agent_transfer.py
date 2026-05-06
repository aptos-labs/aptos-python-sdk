"""Example: Multi-agent transaction where both sender and receiver sign.

Demonstrates manually constructing a multi-agent transaction with
MultiAgentRawTransaction, collecting signatures from multiple parties,
and submitting with a MultiAgentAuthenticator.
"""

import asyncio

from aptos_sdk_v2 import Account, Aptos, AptosConfig, Network
from aptos_sdk_v2.bcs import Serializer
from aptos_sdk_v2.transactions import (
    Authenticator,
    EntryFunction,
    MultiAgentAuthenticator,
    MultiAgentRawTransaction,
    SignedTransaction,
    TransactionArgument,
    TransactionPayload,
)
from aptos_sdk_v2.types import StructTag, TypeTag


async def main():
    config = AptosConfig(network=Network.DEVNET)
    async with Aptos(config) as aptos:
        # Create sender and secondary signer
        alice = Account.generate()
        bob = Account.generate()
        print(f"Alice (sender):           {alice.address}")
        print(f"Bob (secondary signer):   {bob.address}")

        # Fund both accounts
        print("\nFunding accounts...")
        await asyncio.gather(
            aptos.faucet.fund_account(alice.address, 100_000_000),
            aptos.faucet.fund_account(bob.address, 10_000_000),
        )

        # Build a transfer payload (Alice sends to Bob)
        payload = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
            [
                TransactionArgument(bob.address, Serializer.struct),
                TransactionArgument(5_000, Serializer.u64),
            ],
        )

        # Build a raw transaction for Alice
        raw_txn = await aptos.transaction.build(
            sender=alice.address,
            payload=TransactionPayload(payload),
        )

        # Wrap in MultiAgentRawTransaction with Bob as secondary signer
        multi_agent_txn = MultiAgentRawTransaction(raw_txn, [bob.address])

        # Both parties sign the multi-agent transaction
        alice_auth = multi_agent_txn.sign(alice.private_key)
        bob_auth = multi_agent_txn.sign(bob.private_key)

        # Construct the top-level authenticator
        authenticator = Authenticator(
            MultiAgentAuthenticator(
                sender=alice_auth,
                secondary_signers=[(bob.address, bob_auth)],
            )
        )

        # Create and submit the signed transaction
        signed_txn = SignedTransaction(raw_txn, authenticator)
        txn_hash = await aptos.transaction.submit(signed_txn)
        print(f"\nSubmitted multi-agent transaction: {txn_hash}")

        result = await aptos.transaction.wait_for_transaction(txn_hash)
        print(f"Success: {result['success']}")

        # Check balances
        alice_balance = await aptos.coin.balance(alice.address)
        bob_balance = await aptos.coin.balance(bob.address)
        print(f"\nAlice balance: {alice_balance}")
        print(f"Bob balance:   {bob_balance}")


if __name__ == "__main__":
    asyncio.run(main())
