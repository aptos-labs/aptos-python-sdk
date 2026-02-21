# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Integration tests for Secp256k1 ECDSA account operations.

These tests require a live Aptos network (devnet or localnet).
"""

import pytest

from aptos_sdk.account import Account
from aptos_sdk.asymmetric_crypto import PrivateKeyVariant
from aptos_sdk.async_client import FaucetClient, RestClient

pytestmark = pytest.mark.integration


class TestSecp256k1Transfer:
    async def test_fund_and_transfer(
        self, rest_client: RestClient, faucet_client: FaucetClient
    ):
        """Secp256k1 accounts should be able to fund and transfer APT."""
        alice = Account.generate(PrivateKeyVariant.SECP256K1)
        bob = Account.generate(PrivateKeyVariant.SECP256K1)

        await faucet_client.fund_account(alice.address, 100_000_000)
        await faucet_client.fund_account(bob.address, 1)

        bob_initial = await rest_client.account_balance(bob.address)

        txn_hash = await rest_client.bcs_transfer(alice, bob.address, 5_000)
        await rest_client.wait_for_transaction(txn_hash)

        bob_final = await rest_client.account_balance(bob.address)
        assert bob_final == bob_initial + 5_000

    async def test_multiple_secp256k1_transfers(
        self, rest_client: RestClient, faucet_client: FaucetClient
    ):
        """Multiple sequential transfers with Secp256k1 should succeed."""
        alice = Account.generate(PrivateKeyVariant.SECP256K1)
        bob = Account.generate(PrivateKeyVariant.SECP256K1)

        await faucet_client.fund_account(alice.address, 100_000_000)
        await faucet_client.fund_account(bob.address, 1)

        for _ in range(2):
            txn_hash = await rest_client.bcs_transfer(alice, bob.address, 1_000)
            await rest_client.wait_for_transaction(txn_hash)

        bob_balance = await rest_client.account_balance(bob.address)
        assert bob_balance >= 2_000
