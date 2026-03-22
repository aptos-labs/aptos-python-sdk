"""Integration test: view functions on devnet."""

import pytest


@pytest.mark.integration
async def test_view_function(aptos, funded_account):
    result = await aptos.general.view(
        "0x1::coin",
        "balance",
        ["0x1::aptos_coin::AptosCoin"],
        [str(funded_account.address)],
    )
    assert len(result) == 1
    balance = int(result[0])
    assert balance > 0
