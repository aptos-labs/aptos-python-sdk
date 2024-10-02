# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio
import os
import sys

from aptos_sdk.account import Account
from aptos_sdk.aptos_cli_wrapper import AptosCLIWrapper
from aptos_sdk.async_client import FaucetClient, RestClient
from aptos_sdk.package_publisher import MODULE_ADDRESS, PackagePublisher, PublishMode

from .common import APTOS_CORE_PATH, FAUCET_URL, NODE_URL


async def main(package_dir):
    rest_client = RestClient(NODE_URL)
    faucet_client = FaucetClient(FAUCET_URL, rest_client)
    package_publisher = PackagePublisher(rest_client)
    alice = Account.generate()

    print("\n=== Publisher Address ===")
    print(f"Alice: {alice.address()}")

    await faucet_client.fund_account(alice.address(), 100_000_000)

    print("\n=== Initial Coin Balance ===")
    alice_balance = await rest_client.account_balance(alice.address())
    print(f"Alice: {alice_balance}")

    # The object address is derived from publisher's address and sequence number.
    code_object_address = await package_publisher.derive_object_address(alice.address())
    module_name = "hello_blockchain"

    print("\nCompiling package...")
    if AptosCLIWrapper.does_cli_exist():
        AptosCLIWrapper.compile_package(package_dir, {module_name: code_object_address})
    else:
        print(f"Address of the object to be created: {code_object_address}")
        input(
            "\nUpdate the module with the derived code object address, compile, and press enter."
        )

    # Deploy package to code object.
    print("\n=== Object Code Deployment ===")
    deploy_txn_hash = await package_publisher.publish_package_in_path(
        alice, package_dir, MODULE_ADDRESS, publish_mode=PublishMode.OBJECT_DEPLOY
    )

    print(f"Tx submitted: {deploy_txn_hash[0]}")
    await rest_client.wait_for_transaction(deploy_txn_hash[0])
    print(f"Package deployed to object {code_object_address}")

    print("\n=== Object Code Upgrade ===")
    upgrade_txn_hash = await package_publisher.publish_package_in_path(
        alice,
        package_dir,
        MODULE_ADDRESS,
        publish_mode=PublishMode.OBJECT_UPGRADE,
        code_object=code_object_address,
    )
    print(f"Tx submitted: {upgrade_txn_hash[0]}")
    await rest_client.wait_for_transaction(upgrade_txn_hash[0])
    print(f"Package in object {code_object_address} upgraded")
    await rest_client.close()


if __name__ == "__main__":
    if len(sys.argv) == 2:
        package_dir = sys.argv[1]
    else:
        package_dir = os.path.join(
            APTOS_CORE_PATH,
            "aptos-move",
            "move-examples",
            "hello_blockchain",
        )

    asyncio.run(main(package_dir))
