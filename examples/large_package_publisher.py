# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
This example demonstrates publishing large Move packages which cannot fit in a single transaction, using the most
abstract method `compile_and_publish_move_package` from the `PackagePublisher` class. This method handles all necessary
steps for compiling and publishing both regular and large packages.

Note: This method requires the presence of the Aptos CLI in `APTOS_CLI_PATH`. As an alternative, if you want finer
control over the process or do not want to rely on the CLI, you may use `publish_package_in_path`, which is
demonstrated in the `object_code_deployment.py` example.
"""

import asyncio
import os
import sys

import aptos_sdk.cli as aptos_sdk_cli
from aptos_sdk.account import Account
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.async_client import ClientConfig, FaucetClient, RestClient
from aptos_sdk.package_publisher import MODULE_ADDRESS, PackagePublisher, PublishMode

from .common import APTOS_CORE_PATH, FAUCET_AUTH_TOKEN, FAUCET_URL, NODE_URL


async def publish_large_packages(large_packages_dir) -> AccountAddress:
    """
    Publish the `large_packages.move` module under Alice's account for localnet tests.
    This module is not yet part of the Aptos framework, so it must be manually published for testing.
    """
    rest_client = RestClient(NODE_URL)
    faucet_client = FaucetClient(FAUCET_URL, rest_client, FAUCET_AUTH_TOKEN)

    alice = Account.generate()
    await faucet_client.fund_account(alice.address(), 1_000_000_000)
    await aptos_sdk_cli.publish_package(
        large_packages_dir, {"large_packages": alice.address()}, alice, NODE_URL
    )
    return alice.address()


async def main(
    large_package_example_dir,
    large_packages_module_address: AccountAddress = MODULE_ADDRESS,
):
    client_config = ClientConfig()
    client_config.transaction_wait_in_seconds = 120
    client_config.max_gas_amount = 1_000_000
    rest_client = RestClient(NODE_URL, client_config)
    faucet_client = FaucetClient(FAUCET_URL, rest_client, FAUCET_AUTH_TOKEN)
    publisher = PackagePublisher(rest_client)

    alice = Account.generate()
    req0 = faucet_client.fund_account(alice.address(), 1_000_000_000)
    req1 = faucet_client.fund_account(alice.address(), 1_000_000_000)
    req2 = faucet_client.fund_account(alice.address(), 1_000_000_000)
    await asyncio.gather(*[req0, req1, req2])
    alice_balance = await rest_client.account_balance(alice.address())
    print(f"Alice: {alice.address()} {alice_balance}")

    # Name of the move module for the package to be published, containing artifacts larger than the MAX_CHUNK_SIZE
    module_name = "large_package_example"

    # -- Example 1. Account deployment
    print("=== Publishing large package to account ===")

    account_deploy_txn_hash = await publisher.compile_and_publish_move_package(
        alice, large_package_example_dir, module_name, large_packages_module_address
    )

    print(f"Tx submitted: {account_deploy_txn_hash[0]}")
    await rest_client.wait_for_transaction(account_deploy_txn_hash[0])
    print("Transaction completed.")

    # ----- Example 2. Object code deployment
    print("=== Publishing large package to object ===")

    object_deploy_txn_hash = await publisher.compile_and_publish_move_package(
        alice,
        large_package_example_dir,
        module_name,
        large_packages_module_address,
        PublishMode.OBJECT_DEPLOY,
    )

    print(f"The last tx submitted: {object_deploy_txn_hash[-1]}")
    await rest_client.wait_for_transaction(object_deploy_txn_hash[-1])
    print("Transaction completed.")

    await rest_client.close()


if __name__ == "__main__":
    if len(sys.argv) == 2:
        large_package_example_dir = sys.argv[1]
    else:
        large_package_example_dir = os.path.join(
            APTOS_CORE_PATH,
            "aptos-move",
            "move-examples",
            "large_packages",
            "large_package_example",
        )
    asyncio.run(main(large_package_example_dir))
