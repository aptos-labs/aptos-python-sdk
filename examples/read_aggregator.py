# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio

from aptos_sdk.account_address import AccountAddress
from aptos_sdk.async_client import RestClient

from .common import CLIENT_CONFIG, NODE_URL


async def main():
    rest_client = RestClient(NODE_URL, client_config=CLIENT_CONFIG)
    # CoinInfo.supply is an OptionalAggregator: parallelizable aggregator on
    # long-lived networks, integer on localnet. aggregator_value handles both.
    total_apt = await rest_client.aggregator_value(
        AccountAddress.from_str("0x1"),
        "0x1::coin::CoinInfo<0x1::aptos_coin::AptosCoin>",
        ["supply"],
    )
    print(f"Total circulating APT: {total_apt}")
    await rest_client.close()


if __name__ == "__main__":
    asyncio.run(main())
