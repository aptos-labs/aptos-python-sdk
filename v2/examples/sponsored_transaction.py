"""Example: Sponsored (fee-payer) transaction where a sponsor pays gas fees.

Demonstrates using FeePayerRawTransaction so that Alice sends a transfer
but Sponsor pays the gas cost.
"""

import asyncio

from aptos_sdk_v2 import Account, Aptos, AptosConfig, Network
from aptos_sdk_v2.bcs import Serializer
from aptos_sdk_v2.transactions import (
    Authenticator,
    EntryFunction,
    FeePayerAuthenticator,
    FeePayerRawTransaction,
    SignedTransaction,
    TransactionArgument,
    TransactionPayload,
)
from aptos_sdk_v2.types import StructTag, TypeTag


async def main():
    config = AptosConfig(network=Network.DEVNET)
    async with Aptos(config) as aptos:
        alice = Account.generate()
        bob = Account.generate()
        sponsor = Account.generate()
        print(f"Alice (sender):    {alice.address}")
        print(f"Bob (recipient):   {bob.address}")
        print(f"Sponsor (payer):   {sponsor.address}")

        # Fund accounts — Alice gets minimal funds, Sponsor gets more for gas
        print("\nFunding accounts...")
        await asyncio.gather(
            aptos.faucet.fund_account(alice.address, 100_000_000),
            aptos.faucet.fund_account(bob.address, 10_000_000),
            aptos.faucet.fund_account(sponsor.address, 100_000_000),
        )

        alice_before = await aptos.coin.balance(alice.address)
        sponsor_before = await aptos.coin.balance(sponsor.address)

        # Build the transfer payload
        payload = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
            [
                TransactionArgument(bob.address, Serializer.struct),
                TransactionArgument(10_000, Serializer.u64),
            ],
        )

        # Build a raw transaction for Alice
        raw_txn = await aptos.transaction.build(
            sender=alice.address,
            payload=TransactionPayload(payload),
        )

        # Wrap in FeePayerRawTransaction with Sponsor paying gas
        fee_payer_txn = FeePayerRawTransaction(
            raw_txn, secondary_signers=[], fee_payer=sponsor.address
        )

        # Both Alice (sender) and Sponsor (fee payer) sign
        alice_auth = fee_payer_txn.sign(alice.private_key)
        sponsor_auth = fee_payer_txn.sign(sponsor.private_key)

        # Construct the fee-payer authenticator
        authenticator = Authenticator(
            FeePayerAuthenticator(
                sender=alice_auth,
                secondary_signers=[],
                fee_payer=(sponsor.address, sponsor_auth),
            )
        )

        # Submit
        signed_txn = SignedTransaction(raw_txn, authenticator)
        txn_hash = await aptos.transaction.submit(signed_txn)
        print(f"\nSubmitted sponsored transaction: {txn_hash}")

        result = await aptos.transaction.wait_for_transaction(txn_hash)
        print(f"Success: {result['success']}")
        print(f"Gas used: {result['gas_used']}")

        # Show who paid the gas
        alice_after = await aptos.coin.balance(alice.address)
        sponsor_after = await aptos.coin.balance(sponsor.address)
        bob_after = await aptos.coin.balance(bob.address)

        print(f"\nAlice spent:   {alice_before - alice_after} (should be exactly 10000 — no gas)")
        print(f"Sponsor spent: {sponsor_before - sponsor_after} (gas cost)")
        print(f"Bob received:  {bob_after - 10_000_000}")


if __name__ == "__main__":
    asyncio.run(main())
