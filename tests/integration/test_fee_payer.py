# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Integration tests for sponsored (fee-payer) transactions.

These tests require a live Aptos network (devnet or localnet).
"""

import pytest

from aptos_sdk.account import Account
from aptos_sdk.async_client import FaucetClient, RestClient
from aptos_sdk.authenticator import FeePayerAuthenticator, TransactionAuthenticator
from aptos_sdk.bcs import Serializer
from aptos_sdk.transactions import (
    EntryFunction,
    FeePayerRawTransaction,
    SignedTransaction,
    TransactionArgument,
    TransactionPayload,
)

pytestmark = pytest.mark.integration


class TestFeePayerTransaction:
    async def test_sponsored_account_creation(
        self, rest_client: RestClient, faucet_client: FaucetClient
    ):
        """A sponsor should be able to pay gas for another account's transaction."""
        alice = Account.generate()
        bob = Account.generate()
        sponsor = Account.generate()

        await faucet_client.fund_account(sponsor.address, 100_000_000)

        alice_seq = await rest_client.account_sequence_number(alice.address)

        payload = EntryFunction.natural(
            "0x1::aptos_account",
            "create_account",
            [],
            [TransactionArgument(bob.address, Serializer.struct)],
        )
        raw_txn = await rest_client.create_bcs_transaction(
            alice, TransactionPayload(payload), alice_seq
        )

        # Sign with unknown fee payer first (sender signs)
        fee_payer_txn = FeePayerRawTransaction(raw_txn, [], None)
        sender_auth = alice.sign_transaction(fee_payer_txn)

        # Then sign with known fee payer (sponsor signs)
        fee_payer_txn = FeePayerRawTransaction(raw_txn, [], sponsor.address)
        sponsor_auth = sponsor.sign_transaction(fee_payer_txn)

        fee_payer_authenticator = FeePayerAuthenticator(
            sender_auth, [], (sponsor.address, sponsor_auth)  # type: ignore[arg-type]
        )
        signed_txn = SignedTransaction(
            raw_txn, TransactionAuthenticator(fee_payer_authenticator)
        )

        txn_hash = await rest_client.submit_bcs_transaction(signed_txn)
        await rest_client.wait_for_transaction(txn_hash)

        # Bob should now exist on chain
        bob_seq = await rest_client.account_sequence_number(bob.address)
        assert bob_seq == 0

        # Alice's sequence number should have incremented
        alice_seq_after = await rest_client.account_sequence_number(alice.address)
        assert alice_seq_after == 1

        # Sponsor should have paid gas (balance decreased)
        sponsor_balance = await rest_client.account_balance(sponsor.address)
        assert sponsor_balance < 100_000_000
