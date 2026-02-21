# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Legacy test harness that runs examples as integration tests.

This module is invoked via ``make integration_test`` in CI (localnet workflow).
Each test simply calls the ``main()`` coroutine of the corresponding example.
"""

import unittest


class Test(unittest.IsolatedAsyncioTestCase):
    async def test_fee_payer_transfer_coin(self):
        from . import fee_payer_transfer_coin

        await fee_payer_transfer_coin.main()

    async def test_secp256k1_ecdsa_transfer_coin(self):
        from . import secp256k1_ecdsa_transfer_coin

        await secp256k1_ecdsa_transfer_coin.main()

    async def test_simulate_transfer_coin(self):
        from . import simulate_transfer_coin

        await simulate_transfer_coin.main()

    async def test_transfer_coin(self):
        from . import transfer_coin

        await transfer_coin.main()


if __name__ == "__main__":
    unittest.main(buffer=True)
