# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0
import asyncio
import os
import sys

import aptos_sdk.cli as aptos_sdk_cli
from aptos_sdk.account import Account
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.aptos_cli_wrapper import AptosCLIWrapper
from aptos_sdk.async_client import ClientConfig, FaucetClient, RestClient
from aptos_sdk.package_publisher import MODULE_ADDRESS, PackagePublisher, PublishMode

from .common import APTOS_CORE_PATH, FAUCET_URL, NODE_URL


async def publish_large_packages(large_packages_dir) -> AccountAddress:
    rest_client = RestClient(NODE_URL)
    faucet_client = FaucetClient(FAUCET_URL, rest_client)

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
    faucet_client = FaucetClient(FAUCET_URL, rest_client)
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

    # Example 1. Account deployment
    print("=== Publishing large package to account ===")

    if AptosCLIWrapper.does_cli_exist():
        AptosCLIWrapper.compile_package(
            large_package_example_dir, {module_name: alice.address()}
        )
    else:
        input("\nUpdate the module with Alice's address, compile, and press Enter.")

    account_deploy_txn_hash = await publisher.publish_package_in_path(
        alice, large_package_example_dir, large_packages_module_address
    )

    print(f"Tx submitted: {account_deploy_txn_hash[0]}")
    await rest_client.wait_for_transaction(account_deploy_txn_hash[0])
    print(f"Package deployed to account {alice.address()}")

    # Example 2. Object code deployment
    # Note: Here we assume that we already know we should use the chunked publish mode, so we run a preliminary build.
    print("=== Publishing large package to object ===")

    # Calculate the number of transactions needed for the chunked publish to predict the code object address.
    # Start by deriving the address assuming a single transaction for a preliminary build to estimate artifact size.
    code_object_address = await publisher.derive_object_address(alice.address())

    print("\nCompiling package as a preliminary build...")
    if AptosCLIWrapper.does_cli_exist():
        AptosCLIWrapper.compile_package(
            large_package_example_dir, {module_name: code_object_address}
        )
    else:
        print(f"Address of the object to be created: {code_object_address}")
        input(
            "\nUpdate the module with the derived code object address, compile, and press enter."
        )

    metadata, modules = publisher.load_package_artifacts(large_package_example_dir)

    # Number of transactions required for the chunked publish.
    required_txns = len(
        publisher.prepare_chunked_payloads(
            metadata,
            modules,
            large_packages_module_address,
            PublishMode.OBJECT_DEPLOY,
        )
    )

    if required_txns > 1:
        code_object_address = await publisher.derive_object_address(
            alice.address(), required_txns
        )
        print("\nCompiling the package with updated object address...")
        if AptosCLIWrapper.does_cli_exist():
            AptosCLIWrapper.compile_package(
                large_package_example_dir, {module_name: code_object_address}
            )
        else:
            print(f"Address of the object to be created: {code_object_address}")
            input(
                "\nUpdate the module with the derived code object address, compile, and press enter."
            )

    object_deploy_txn_hash = await publisher.publish_package_in_path(
        alice,
        large_package_example_dir,
        large_packages_module_address,
        PublishMode.OBJECT_DEPLOY,
    )

    print(f"The last tx submitted: {object_deploy_txn_hash[-1]}")
    await rest_client.wait_for_transaction(object_deploy_txn_hash[-1])
    print(f"Package deployed to object {code_object_address}")

    # Example 3. Object code upgrade
    print("=== Upgrading large package object ===")

    object_upgrade_txn_hash = await publisher.publish_package_in_path(
        alice,
        large_package_example_dir,
        large_packages_module_address,
        PublishMode.OBJECT_UPGRADE,
        code_object_address,
    )

    print(f"The last tx submitted: {object_upgrade_txn_hash[-1]}")
    await rest_client.wait_for_transaction(object_upgrade_txn_hash[-1])
    print(f"Package in object {code_object_address} upgraded")
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
