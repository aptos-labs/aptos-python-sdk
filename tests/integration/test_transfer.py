# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Integration tests for account funding, balance queries, and APT transfers.

These tests require a live Aptos network (devnet or localnet).
Run with:  pytest tests/integration/ -m integration -v
"""

import pytest

from aptos_sdk.account import Account
from aptos_sdk.async_client import FaucetClient, RestClient

pytestmark = pytest.mark.integration


class TestFundAndBalance:
    async def test_fund_account_creates_account(
        self, rest_client: RestClient, faucet_client: FaucetClient
    ):
        """Funding a new account should create it and set the balance."""
        alice = Account.generate()
        await faucet_client.fund_account(alice.address, 100_000_000)
        balance = await rest_client.account_balance(alice.address)
        assert balance >= 100_000_000

    async def test_account_sequence_number_starts_at_zero(
        self, rest_client: RestClient, funded_account: Account
    ):
        """A freshly funded account should have sequence number 0."""
        seq = await rest_client.account_sequence_number(funded_account.address)
        assert seq == 0

    async def test_nonexistent_account_sequence_number_is_zero(
        self, rest_client: RestClient
    ):
        """A non-existent account should return sequence number 0."""
        phantom = Account.generate()
        seq = await rest_client.account_sequence_number(phantom.address)
        assert seq == 0

    async def test_get_account(self, rest_client: RestClient, funded_account: Account):
        """get_account should return a valid AccountInfo."""
        info = await rest_client.get_account(funded_account.address)
        assert info.sequence_number == 0
        assert info.authentication_key is not None


class TestBcsTransfer:
    async def test_transfer_apt(
        self, rest_client: RestClient, faucet_client: FaucetClient
    ):
        """Transfer APT from Alice to Bob and verify balances change."""
        alice = Account.generate()
        bob = Account.generate()
        await faucet_client.fund_account(alice.address, 100_000_000)
        await faucet_client.fund_account(bob.address, 1)

        bob_initial = await rest_client.account_balance(bob.address)

        txn_hash = await rest_client.bcs_transfer(alice, bob.address, 1_000)
        await rest_client.wait_for_transaction(txn_hash)

        bob_final = await rest_client.account_balance(bob.address)
        assert bob_final == bob_initial + 1_000

    async def test_transfer_increments_sequence_number(
        self, rest_client: RestClient, faucet_client: FaucetClient
    ):
        """A successful transfer should increment the sender's sequence number."""
        alice = Account.generate()
        bob = Account.generate()
        await faucet_client.fund_account(alice.address, 100_000_000)
        await faucet_client.fund_account(bob.address, 1)

        txn_hash = await rest_client.bcs_transfer(alice, bob.address, 1_000)
        await rest_client.wait_for_transaction(txn_hash)

        seq = await rest_client.account_sequence_number(alice.address)
        assert seq == 1

    async def test_multiple_transfers(
        self, rest_client: RestClient, faucet_client: FaucetClient
    ):
        """Multiple sequential transfers should all succeed."""
        alice = Account.generate()
        bob = Account.generate()
        await faucet_client.fund_account(alice.address, 100_000_000)
        await faucet_client.fund_account(bob.address, 1)

        for _ in range(3):
            txn_hash = await rest_client.bcs_transfer(alice, bob.address, 500)
            await rest_client.wait_for_transaction(txn_hash)

        bob_balance = await rest_client.account_balance(bob.address)
        assert bob_balance >= 1_500

        seq = await rest_client.account_sequence_number(alice.address)
        assert seq == 3


class TestWaitForTransaction:
    async def test_wait_returns_transaction(
        self, rest_client: RestClient, faucet_client: FaucetClient
    ):
        """wait_for_transaction should return the confirmed transaction."""
        alice = Account.generate()
        bob = Account.generate()
        await faucet_client.fund_account(alice.address, 100_000_000)
        await faucet_client.fund_account(bob.address, 1)

        txn_hash = await rest_client.bcs_transfer(alice, bob.address, 1_000)
        txn = await rest_client.wait_for_transaction(txn_hash)
        assert txn is not None
