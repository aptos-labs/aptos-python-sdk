"""Integration test: APT transfer on devnet."""

import pytest

from aptos_sdk_v2 import Account


@pytest.mark.integration
async def test_transfer_apt(aptos, funded_account):
    alice = funded_account
    bob = Account.generate()

    # Fund Bob so account exists
    await aptos.faucet.fund_account(bob.address, 10_000_000)

    # Transfer APT
    txn_hash = await aptos.coin.transfer(alice, bob.address, 1_000)
    result = await aptos.transaction.wait_for_transaction(txn_hash)
    assert result["success"] is True

    # Verify balance increased
    balance = await aptos.coin.balance(bob.address)
    assert balance >= 10_001_000
