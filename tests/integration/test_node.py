# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Integration tests for node queries (ledger info, resources, view functions).

These tests require a live Aptos network (devnet or localnet).
"""

import pytest

from aptos_sdk.account import Account
from aptos_sdk.async_client import FaucetClient, RestClient
from aptos_sdk.errors import NotFoundError

pytestmark = pytest.mark.integration


class TestLedgerInfo:
    async def test_get_ledger_info(self, rest_client: RestClient):
        """Ledger info should return valid chain state."""
        info = await rest_client.get_ledger_info()
        assert info.chain_id > 0
        assert info.ledger_version >= 0
        assert info.block_height >= 0
        assert info.epoch >= 0

    async def test_chain_id(self, rest_client: RestClient):
        """chain_id() should return a positive integer."""
        chain_id = await rest_client.chain_id()
        assert chain_id > 0


class TestAccountEndpoint:
    async def test_get_account(
        self, rest_client: RestClient, faucet_client: FaucetClient
    ):
        """A funded account should be queryable via the /accounts endpoint."""
        alice = Account.generate()
        await faucet_client.fund_account(alice.address, 100_000_000)
        info = await rest_client.get_account(alice.address)
        assert info.sequence_number == 0
        assert info.authentication_key is not None

    async def test_get_nonexistent_account(self, rest_client: RestClient):
        """Querying a non-existent account should raise or return defaults.

        On localnet: raises NotFoundError.
        On devnet: returns a default AccountInfo with sequence_number=0.
        """
        phantom = Account.generate()
        try:
            info = await rest_client.get_account(phantom.address)
            # Devnet returns defaults for non-existent accounts
            assert info.sequence_number == 0
        except NotFoundError:
            # Localnet returns 404 — expected behavior
            pass


class TestResources:
    async def test_account_resource(
        self, rest_client: RestClient, faucet_client: FaucetClient
    ):
        """A funded account should have resources available.

        Note: On devnet (resource groups), the REST /resource endpoint may
        return 404 even for funded accounts. Resources are only accessible
        via view functions. On localnet, the REST endpoint works normally.
        """
        alice = Account.generate()
        await faucet_client.fund_account(alice.address, 100_000_000)

        try:
            resource = await rest_client.get_account_resource(
                alice.address, "0x1::account::Account"
            )
            assert "sequence_number" in resource.data
        except NotFoundError:
            # Devnet uses resource groups — resources not visible via REST.
            # Verify via view function instead.
            balance = await rest_client.account_balance(alice.address)
            assert balance >= 100_000_000

    async def test_account_resources_list(
        self, rest_client: RestClient, faucet_client: FaucetClient
    ):
        """Listing resources should return items (localnet) or empty (devnet)."""
        alice = Account.generate()
        await faucet_client.fund_account(alice.address, 100_000_000)

        resources = await rest_client.get_account_resources(alice.address)
        if len(resources) > 0:
            # Localnet: standard resource storage
            type_strs = [r.type for r in resources]
            assert "0x1::account::Account" in type_strs
        else:
            # Devnet: resource groups — REST returns empty, but account exists
            info = await rest_client.get_account(alice.address)
            assert info.sequence_number == 0


class TestViewFunction:
    async def test_view_balance(
        self, rest_client: RestClient, faucet_client: FaucetClient
    ):
        """The 0x1::coin::balance view function should return the account balance."""
        alice = Account.generate()
        await faucet_client.fund_account(alice.address, 50_000_000)
        balance = await rest_client.account_balance(alice.address)
        assert balance >= 50_000_000

    async def test_view_nonexistent_balance(self, rest_client: RestClient):
        """Querying balance of a non-existent account should raise or return 0."""
        phantom = Account.generate()
        try:
            balance = await rest_client.account_balance(phantom.address)
            # Some nodes return 0 for non-existent coin stores
            assert balance == 0
        except Exception:
            # Expected — view function aborts for non-existent coin store
            pass
