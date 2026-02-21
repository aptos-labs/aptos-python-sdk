# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Integration tests for transaction simulation.

These tests require a live Aptos network (devnet or localnet).
"""

import pytest

from aptos_sdk.account import Account
from aptos_sdk.async_client import FaucetClient, RestClient
from aptos_sdk.bcs import Serializer
from aptos_sdk.transactions import (
    EntryFunction,
    TransactionArgument,
    TransactionPayload,
)
from aptos_sdk.type_tag import StructTag, TypeTag

pytestmark = pytest.mark.integration


class TestSimulateTransaction:
    async def test_simulate_transfer(
        self, rest_client: RestClient, faucet_client: FaucetClient
    ):
        """Simulating a transfer should return vm_status 'Executed successfully'."""
        alice = Account.generate()
        bob = Account.generate()
        await faucet_client.fund_account(alice.address, 100_000_000)
        await faucet_client.fund_account(bob.address, 1)

        payload = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
            [
                TransactionArgument(bob.address, Serializer.struct),
                TransactionArgument(100_000, Serializer.u64),
            ],
        )
        raw_txn = await rest_client.create_bcs_transaction(
            alice, TransactionPayload(payload)
        )
        result = await rest_client.simulate_transaction(raw_txn, alice)
        # The simulation API returns a JSON array; the SDK passes it through.
        if isinstance(result, list):
            result = result[0]
        assert result["vm_status"] == "Executed successfully"

    async def test_simulate_with_gas_estimation(
        self, rest_client: RestClient, faucet_client: FaucetClient
    ):
        """Simulating with estimate_gas=True should still succeed."""
        alice = Account.generate()
        bob = Account.generate()
        await faucet_client.fund_account(alice.address, 100_000_000)
        await faucet_client.fund_account(bob.address, 1)

        payload = EntryFunction.natural(
            "0x1::aptos_account",
            "transfer",
            [],
            [
                TransactionArgument(bob.address, Serializer.struct),
                TransactionArgument(1_000, Serializer.u64),
            ],
        )
        raw_txn = await rest_client.create_bcs_transaction(
            alice, TransactionPayload(payload)
        )
        result = await rest_client.simulate_transaction(
            raw_txn, alice, estimate_gas=True
        )
        if isinstance(result, list):
            result = result[0]
        assert result["vm_status"] == "Executed successfully"


class TestGasEstimation:
    async def test_estimate_gas_price(self, rest_client: RestClient):
        """Gas estimation should return reasonable values."""
        estimate = await rest_client.estimate_gas_price()
        assert estimate.gas_estimate > 0
        assert (
            estimate.deprioritized_gas_estimate is None
            or estimate.deprioritized_gas_estimate >= 0
        )
        assert (
            estimate.prioritized_gas_estimate is None
            or estimate.prioritized_gas_estimate >= estimate.gas_estimate
        )
