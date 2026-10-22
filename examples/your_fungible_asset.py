# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio
import os
import sys

from aptos_sdk.account import Account, AccountAddress
from aptos_sdk.aptos_cli_wrapper import AptosCLIWrapper
from aptos_sdk.aptos_token_client import FungibleAssetClient
from aptos_sdk.async_client import FaucetClient, RestClient
from aptos_sdk.bcs import Serializer
from aptos_sdk.package_publisher import PackagePublisher
from aptos_sdk.transactions import (
    EntryFunction,
    TransactionArgument,
    TransactionPayload,
)

from .common import FAUCET_URL, NODE_URL


# Admin forcefully transfers the newly created coin to the specified receiver address
async def transfer_coin(
    rest_client: RestClient,
    admin: Account,
    from_addr: AccountAddress,
    to_addr: AccountAddress,
    amount: int,
) -> None:
    payload = EntryFunction.natural(
        f"{admin.address()}::fa_coin",
        "transfer",
        [],
        [
            TransactionArgument(from_addr, Serializer.struct),
            TransactionArgument(to_addr, Serializer.struct),
            TransactionArgument(amount, Serializer.u64),
        ],
    )
    signed_txn = await rest_client.create_bcs_signed_transaction(
        admin, TransactionPayload(payload)
    )
    txn_hash = await rest_client.submit_bcs_transaction(signed_txn)
    await rest_client.wait_for_transaction(txn_hash)


# Admin mint the newly created coin to the specified receiver address
async def mint_coin(
    rest_client: RestClient, admin: Account, receiver: AccountAddress, amount: int
) -> None:
    payload = EntryFunction.natural(
        f"{admin.address()}::fa_coin",
        "mint",
        [],
        [
            TransactionArgument(receiver, Serializer.struct),
            TransactionArgument(amount, Serializer.u64),
        ],
    )
    signed_txn = await rest_client.create_bcs_signed_transaction(
        admin, TransactionPayload(payload)
    )
    txn_hash = await rest_client.submit_bcs_transaction(signed_txn)
    await rest_client.wait_for_transaction(txn_hash)


# Admin burns the newly created coin from the specified receiver address
async def burn_coin(
    rest_client: RestClient, admin: Account, receiver: AccountAddress, amount: int
) -> None:
    payload = EntryFunction.natural(
        f"{admin.address()}::fa_coin",
        "burn",
        [],
        [
            TransactionArgument(receiver, Serializer.struct),
            TransactionArgument(amount, Serializer.u64),
        ],
    )
    signed_txn = await rest_client.create_bcs_signed_transaction(
        admin, TransactionPayload(payload)
    )
    txn_hash = await rest_client.submit_bcs_transaction(signed_txn)
    await rest_client.wait_for_transaction(txn_hash)


# Admin freezes the primary fungible store of the specified account
async def freeze(
    rest_client: RestClient, admin: Account, target_addr: AccountAddress
) -> None:
    payload = EntryFunction.natural(
        f"{admin.address()}::fa_coin",
        "freeze_account",
        [],
        [
            TransactionArgument(target_addr, Serializer.struct),
        ],
    )
    signed_txn = await rest_client.create_bcs_signed_transaction(
        admin, TransactionPayload(payload)
    )
    txn_hash = await rest_client.submit_bcs_transaction(signed_txn)
    await rest_client.wait_for_transaction(txn_hash)


# Admin unfreezes the primary fungible store of the specified account
async def unfreeze(
    rest_client: RestClient, admin: Account, target_addr: AccountAddress
) -> None:
    payload = EntryFunction.natural(
        f"{admin.address()}::fa_coin",
        "unfreeze_account",
        [],
        [
            TransactionArgument(target_addr, Serializer.struct),
        ],
    )
    signed_txn = await rest_client.create_bcs_signed_transaction(
        admin, TransactionPayload(payload)
    )
    txn_hash = await rest_client.submit_bcs_transaction(signed_txn)
    await rest_client.wait_for_transaction(txn_hash)


async def main(facoin_path: str):
    alice = Account.generate()
    bob = Account.generate()
    charlie = Account.generate()

    print("=== Addresses ===")
    print(f"Alice: {alice.address()}")
    print(f"Bob: {bob.address()}")
    print(f"Charlie: {charlie.address()}")

    rest_client = RestClient(NODE_URL)
    faucet_client = FaucetClient(FAUCET_URL, rest_client)

    alice_fund = faucet_client.fund_account(alice.address(), 100_000_000)
    bob_fund = faucet_client.fund_account(bob.address(), 100_000_000)
    await asyncio.gather(*[alice_fund, bob_fund])

    if AptosCLIWrapper.does_cli_exist():
        print("\n=== Compiling FACoin package locally ===")
        AptosCLIWrapper.compile_package(facoin_path, {"FACoin": alice.address()})
    else:
        input("\nUpdate the module with Alice's address, compile, and press enter.")

    # :!:>publish
    module_path = os.path.join(
        facoin_path, "build", "Examples", "bytecode_modules", "fa_coin.mv"
    )
    with open(module_path, "rb") as f:
        module = f.read()

    metadata_path = os.path.join(
        facoin_path, "build", "Examples", "package-metadata.bcs"
    )
    with open(metadata_path, "rb") as f:
        metadata = f.read()

    print("\n===Publishing FACoin package===")
    package_publisher = PackagePublisher(rest_client)
    txn_hash = await package_publisher.publish_package(alice, metadata, [module])
    await rest_client.wait_for_transaction(txn_hash)
    print("Transaction hash:", txn_hash)
    # <:!:publish

    get_metadata_resp = await rest_client.view_bcs_payload(
        f"{alice.address()}::fa_coin", "get_metadata", [], []
    )
    facoin_address = AccountAddress.from_str(get_metadata_resp[0]["inner"])
    print("FACoin address:", facoin_address)

    fa_client = FungibleAssetClient(rest_client)

    print(
        "All the balances in this example refer to balance in primary fungible stores of each account."
    )
    print(
        f"Alice's initial FACoin balance: {await fa_client.balance(facoin_address, alice.address())}."
    )
    print(
        f"Bob's initial FACoin balance: {await fa_client.balance(facoin_address, bob.address())}."
    )
    print(
        f"Charlie's initial FACoin balance: {await fa_client.balance(facoin_address, charlie.address())}."
    )

    print("Alice mints Charlie 100 coins.")
    await mint_coin(rest_client, alice, charlie.address(), 100)

    charlie_primary_store_addr = await fa_client.primary_store_address(
        facoin_address, charlie.address()
    )
    print(f"Charlie primary store address: {charlie_primary_store_addr}")
    print(
        f"Charlie's FACoin: {await fa_client.read_object(AccountAddress.from_str_relaxed(charlie_primary_store_addr))}"
    )

    print("Alice freeze Bob's account.")
    await freeze(rest_client, alice, bob.address())

    print(
        "Alice as the admin forcefully transfers the newly minted coins of Charlie to Bob ignoring that Bob's account is frozen."
    )
    await transfer_coin(rest_client, alice, charlie.address(), bob.address(), 100)
    print(
        f"Bob's updated FACoin balance: {await fa_client.balance(facoin_address, bob.address())}."
    )
    print("Bob is frozen:", await fa_client.is_frozen(facoin_address, bob.address()))

    print("Alice unfreezes Bob's account.")
    await unfreeze(rest_client, alice, bob.address())

    print("Alice burns 50 coins from Bob.")
    await burn_coin(rest_client, alice, bob.address(), 50)
    print(
        f"Bob's updated FACoin balance: {await fa_client.balance(facoin_address, bob.address())}."
    )

    print("Bob transfers 10 coins to Alice as the owner.")
    await fa_client.transfer(bob, facoin_address, alice.address(), 10)
    print(
        f"Alice's updated FACoin balance: {await fa_client.balance(facoin_address, alice.address())}."
    )
    print(
        f"Bob's updated FACoin balance: {await fa_client.balance(facoin_address, bob.address())}."
    )

    print(f"Current FACoin's metadata: f{await fa_client.read_object(facoin_address)}")
    print(f"Name: {await fa_client.name(facoin_address)}")
    print(f"Supply: {await fa_client.supply(facoin_address)}")
    print(f"Maximum: {await fa_client.maximum(facoin_address)}")
    print(f"Decimals: {await fa_client.decimals(facoin_address)}")
    print(f"Icon uri: {await fa_client.icon_uri(facoin_address)}")
    print(f"Project uri: {await fa_client.project_uri(facoin_address)}")

    print("done.")


if __name__ == "__main__":
    assert (
        len(sys.argv) == 2
    ), "Expecting an argument that points to the fa_coin directory."

    asyncio.run(main(sys.argv[1]))
