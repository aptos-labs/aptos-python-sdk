# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Hello Blockchain - Complete example of smart contract deployment and interaction.

This example demonstrates the complete workflow of deploying and interacting with
a Move smart contract on the Aptos blockchain using the Python SDK. It showcases
account management, contract deployment, transaction submission, and state querying.

Features Demonstrated:
- **Account Creation**: Generate new accounts programmatically
- **Faucet Integration**: Fund accounts with test APT tokens
- **Smart Contract Deployment**: Compile and publish Move modules
- **Contract Interaction**: Call smart contract functions
- **State Management**: Read and update on-chain resources
- **Transaction Management**: Submit, wait for, and verify transactions
- **Custom Client**: Extend RestClient with domain-specific methods

Smart Contract Overview:
    The hello_blockchain Move module provides a simple message storage system:
    - **Resource**: `MessageHolder` - stores a string message per account
    - **Function**: `set_message(message: String)` - sets or updates the message
    - **Access**: Messages are stored per account and publicly readable

Workflow:
    1. **Setup Phase**: Create accounts and fund them from the faucet
    2. **Deployment Phase**: Compile and publish the Move smart contract
    3. **Interaction Phase**: Call contract functions to store and retrieve messages
    4. **Verification Phase**: Query blockchain state to verify changes

Prerequisites:
    Before running this example, deploy the hello_blockchain Move module:

    Using Aptos CLI::

        # Install Aptos CLI if not already installed
        curl -fsSL "https://aptos.dev/scripts/install_cli.py" | python3

        # Initialize your account
        aptos init

        # Navigate to the Move example
        cd ~/aptos-core/aptos-move/move-examples/hello_blockchain

        # Publish the module (replace with your address)
        aptos move publish --named-addresses hello_blockchain=<your_address>

    Using this script::

        # Option 1: Use the publish_contract function
        contract_addr = await publish_contract("./path/to/hello_blockchain")

        # Option 2: Run with existing contract
        python -m examples.hello_blockchain <contract_address>

Usage Examples:
    Run with existing contract::

        python -m examples.hello_blockchain 0x123abc...

    Programmatic usage::

        import asyncio
        from examples.hello_blockchain import main, publish_contract
        from aptos_sdk.account_address import AccountAddress

        # Deploy and run
        async def run_example():
            # Option 1: Deploy new contract
            contract_addr = await publish_contract("./hello_blockchain")
            await main(contract_addr)

            # Option 2: Use existing contract
            existing_addr = AccountAddress.from_str("0x123...")
            await main(existing_addr)

        asyncio.run(run_example())

    Custom network configuration::

        import os
        # Switch to testnet
        os.environ["APTOS_NODE_URL"] = "https://api.testnet.aptoslabs.com/v1"
        os.environ["APTOS_FAUCET_URL"] = "https://faucet.testnet.aptoslabs.com"

        # Run example on testnet
        python -m examples.hello_blockchain <contract_address>

Expected Output:
    The script will display:
    - Account addresses for Alice and Bob
    - Initial account balances after funding
    - Message storage and retrieval for both accounts
    - Transaction hashes and confirmations

    Example output::

        === Addresses ===
        Alice: 0xabc123...
        Bob: 0xdef456...

        === Initial Balances ===
        Alice: 10000000
        Bob: 10000000

        === Testing Alice ===
        Initial value: None
        Setting the message to "Hello, Blockchain"
        New value: {'message': 'Hello, Blockchain', 'message_change_events': {...}}

        === Testing Bob ===
        Initial value: None
        Setting the message to "Hello, Blockchain"
        New value: {'message': 'Hello, Blockchain', 'message_change_events': {...}}

Move Smart Contract Structure:
    The hello_blockchain.move file should contain::

        module hello_blockchain::message {
            use std::string::String;
            use std::signer;

            struct MessageHolder has key {
                message: String,
            }

            public entry fun set_message(account: &signer, message: String) {
                let account_addr = signer::address_of(account);
                if (!exists<MessageHolder>(account_addr)) {
                    move_to(account, MessageHolder { message });
                } else {
                    let old_holder = borrow_global_mut<MessageHolder>(account_addr);
                    old_holder.message = message;
                }
            }
        }

Error Handling:
    Common issues and solutions:
    - **Missing Contract**: Ensure the Move module is deployed first
    - **Network Issues**: Check NODE_URL and FAUCET_URL configuration
    - **Insufficient Funds**: Verify faucet funding was successful
    - **Transaction Failures**: Check gas fees and account sequence numbers
    - **Compilation Errors**: Verify Aptos CLI installation and Move.toml

Security Notes:
    - This example uses devnet/testnet only (safe for experimentation)
    - Private keys are generated randomly and not persisted
    - All transactions are publicly visible on the blockchain
    - Smart contracts are immutable once deployed

Learning Objectives:
    After running this example, you should understand:
    1. How to create and fund Aptos accounts programmatically
    2. How to deploy Move smart contracts from Python
    3. How to interact with deployed contracts using entry functions
    4. How to query on-chain resources and verify state changes
    5. How to extend RestClient for domain-specific functionality
"""

import asyncio
import os
import sys
from typing import Any, Dict, Optional

from aptos_sdk.account import Account
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.aptos_cli_wrapper import AptosCLIWrapper
from aptos_sdk.async_client import (
    ClientConfig,
    FaucetClient,
    ResourceNotFound,
    RestClient,
)
from aptos_sdk.bcs import Serializer
from aptos_sdk.package_publisher import PackagePublisher
from aptos_sdk.transactions import (
    EntryFunction,
    TransactionArgument,
    TransactionPayload,
)

from .common import API_KEY, FAUCET_AUTH_TOKEN, FAUCET_URL, NODE_URL


class HelloBlockchainClient(RestClient):
    """Extended REST client with domain-specific methods for hello_blockchain contract.

    This class demonstrates how to extend the base RestClient to add application-specific
    functionality for interacting with a particular smart contract. It encapsulates
    the details of resource queries and transaction construction for the hello_blockchain
    Move module.

    Key Features:
    - **Resource Queries**: Simplified access to MessageHolder resources
    - **Transaction Construction**: Automated entry function payload creation
    - **Error Handling**: Graceful handling of missing resources
    - **Type Safety**: Proper typing for contract-specific operations

    Examples:
        Basic usage::

            client = HelloBlockchainClient("https://api.devnet.aptoslabs.com/v1")

            # Read message (returns None if not set)
            message = await client.get_message(contract_addr, user_addr)

            # Set message (creates or updates MessageHolder resource)
            txn_hash = await client.set_message(contract_addr, account, "Hello!")
            await client.wait_for_transaction(txn_hash)

    Note:
        This pattern of extending RestClient is recommended for applications that
        interact with specific smart contracts frequently. It provides a clean
        abstraction over raw resource queries and transaction construction.
    """

    async def get_message(
        self, contract_address: AccountAddress, account_address: AccountAddress
    ) -> Optional[Dict[str, Any]]:
        """Retrieve the MessageHolder resource for a specific account.

        This method queries the blockchain for the MessageHolder resource stored
        under the given account address. The resource is created by the hello_blockchain
        Move module when a user calls set_message for the first time.

        Args:
            contract_address: The address where the hello_blockchain module is published.
            account_address: The account address to query for the MessageHolder resource.

        Returns:
            Dictionary containing the MessageHolder resource data if it exists,
            including the 'message' field and any event handles. Returns None
            if the account has never called set_message.

        Examples:
            Query existing message::

                message_data = await client.get_message(contract_addr, alice.address())
                if message_data:
                    print(f"Alice's message: {message_data['message']}")
                else:
                    print("Alice hasn't set a message yet")

        Note:
            This method handles the ResourceNotFound exception gracefully by
            returning None, making it safe to call even for accounts that haven't
            interacted with the contract yet.
        """
        try:
            return await self.account_resource(
                account_address, f"{contract_address}::message::MessageHolder"
            )
        except ResourceNotFound:
            return None

    async def set_message(
        self, contract_address: AccountAddress, sender: Account, message: str
    ) -> str:
        """Set or update the message in the sender's MessageHolder resource.

        This method constructs and submits a transaction that calls the set_message
        entry function in the hello_blockchain Move module. The function will either
        create a new MessageHolder resource (if this is the first call) or update
        the existing message.

        Args:
            contract_address: The address where the hello_blockchain module is published.
            sender: The account that will sign and send the transaction.
            message: The string message to store in the MessageHolder resource.

        Returns:
            The transaction hash as a string. Use wait_for_transaction() to
            confirm the transaction was processed successfully.

        Raises:
            ApiError: If the transaction submission fails due to network issues,
                insufficient funds, or other blockchain-related errors.

        Examples:
            Set a new message::

                # Send transaction
                txn_hash = await client.set_message(
                    contract_addr,
                    alice,
                    "Hello, Aptos blockchain!"
                )

                # Wait for confirmation
                result = await client.wait_for_transaction(txn_hash)
                print(f"Transaction successful: {result['success']}")

            Update existing message::

                # This will update the existing MessageHolder resource
                await client.set_message(contract_addr, alice, "Updated message!")

        Note:
            The Move smart contract automatically handles whether to create a new
            MessageHolder resource or update an existing one. The gas cost is
            slightly higher for the first call (resource creation) compared to
            subsequent updates.
        """
        payload = EntryFunction.natural(
            f"{contract_address}::message",
            "set_message",
            [],
            [TransactionArgument(message, Serializer.str)],
        )
        signed_transaction = await self.create_bcs_signed_transaction(
            sender, TransactionPayload(payload)
        )
        return await self.submit_bcs_transaction(signed_transaction)


async def publish_contract(package_dir: str) -> AccountAddress:
    """Deploy the hello_blockchain Move package to the Aptos blockchain.

    This function demonstrates the complete smart contract deployment workflow:
    1. Generate a new publisher account
    2. Fund the account from the faucet
    3. Compile the Move package using Aptos CLI
    4. Extract compiled bytecode and metadata
    5. Publish the package to the blockchain

    The deployment process creates a new account specifically for publishing
    the contract, which becomes the address where the hello_blockchain module
    is permanently stored on the blockchain.

    Args:
        package_dir: Path to the Move package directory containing Move.toml
            and the source files. Should contain the hello_blockchain module.

    Returns:
        AccountAddress of the deployed contract (same as publisher address).
        This address is used to interact with the contract functions.

    Raises:
        Exception: If Move compilation fails due to syntax errors or missing files.
        ApiError: If blockchain operations fail (funding, publishing, etc.).
        FileNotFoundError: If compiled bytecode files are not found after compilation.

    Examples:
        Deploy from local package::

            contract_address = await publish_contract(
                "./aptos-move/move-examples/hello_blockchain"
            )
            print(f"Contract deployed at: {contract_address}")

        Deploy and interact::

            # Deploy the contract
            contract_addr = await publish_contract("./hello_blockchain")

            # Use the returned address for interactions
            client = HelloBlockchainClient(NODE_URL)
            txn = await client.set_message(contract_addr, account, "Hello!")

    Directory Structure Expected::

        package_dir/
        ├── Move.toml              # Package configuration
        ├── sources/
        │   └── message.move       # The hello_blockchain module
        └── build/                 # Generated after compilation
            └── Examples/
                ├── package-metadata.bcs
                └── bytecode_modules/
                    └── message.mv

    Move.toml Configuration::

        [package]
        name = "Examples"
        version = "1.0.0"

        [addresses]
        hello_blockchain = "_"

        [dependencies]
        AptosFramework = { git = "https://github.com/aptos-labs/aptos-core.git", ... }

    Note:
        - The function generates a fresh account for each deployment
        - Named addresses are automatically resolved during compilation
        - The deployment transaction is confirmed before returning
        - The REST client is properly closed to prevent resource leaks
    """
    # Generate a new account specifically for contract publishing
    contract_publisher = Account.generate()
    rest_client = RestClient(NODE_URL, client_config=ClientConfig(api_key=API_KEY))
    faucet_client = FaucetClient(FAUCET_URL, rest_client, FAUCET_AUTH_TOKEN)

    # Fund the publisher account with enough APT for deployment
    await faucet_client.fund_account(contract_publisher.address(), 10_000_000)

    # Compile the Move package with the publisher address as hello_blockchain
    AptosCLIWrapper.compile_package(
        package_dir, {"hello_blockchain": contract_publisher.address()}
    )

    # Read the compiled bytecode module
    module_path = os.path.join(
        package_dir, "build", "Examples", "bytecode_modules", "message.mv"
    )
    with open(module_path, "rb") as f:
        module = f.read()

    # Read the package metadata
    metadata_path = os.path.join(
        package_dir, "build", "Examples", "package-metadata.bcs"
    )
    with open(metadata_path, "rb") as f:
        metadata = f.read()

    # Publish the package to the blockchain
    package_publisher = PackagePublisher(rest_client)
    txn_hash = await package_publisher.publish_package(
        contract_publisher, metadata, [module]
    )

    # Wait for deployment transaction to be confirmed
    await rest_client.wait_for_transaction(txn_hash)

    # Clean up resources
    await rest_client.close()

    return contract_publisher.address()


async def main(contract_address: AccountAddress):
    """Execute the hello_blockchain smart contract interaction demo.

    This function demonstrates a complete smart contract interaction workflow
    by creating test accounts, funding them, and showing how multiple users
    can interact with the deployed hello_blockchain contract independently.

    The demo showcases:
    1. **Account Generation**: Create Alice and Bob accounts programmatically
    2. **Faucet Funding**: Fund both accounts with test APT tokens
    3. **Balance Verification**: Check account balances after funding
    4. **Contract Interaction**: Each account sets their own message
    5. **State Queries**: Read back the stored messages to verify success
    6. **Resource Management**: Properly close network connections

    Args:
        contract_address: The address where the hello_blockchain module is deployed.
            This should be the address returned from publish_contract() or obtained
            from a previous deployment.

    Workflow:
        1. Generate two test accounts (Alice and Bob)
        2. Fund both accounts with 10 APT each from the faucet
        3. Display account addresses and balances
        4. For each account:
           - Query initial message state (should be None)
           - Set a message using the smart contract
           - Query the updated state to verify the message was stored
        5. Clean up network connections

    Examples:
        Run with deployed contract::

            from aptos_sdk.account_address import AccountAddress

            contract_addr = AccountAddress.from_str("0xabc123...")
            await main(contract_addr)

        End-to-end deployment and interaction::

            # Deploy first, then interact
            contract_addr = await publish_contract("./hello_blockchain")
            await main(contract_addr)

    Expected Behavior:
        - Alice and Bob can each store independent messages
        - Messages are persistent on the blockchain
        - Each account's MessageHolder resource is separate
        - All transactions should complete successfully

    Error Scenarios:
        - Contract not deployed at the given address
        - Faucet funding failures (network issues, rate limits)
        - Transaction failures (insufficient gas, network problems)
        - Resource query failures (node connectivity issues)

    Note:
        This function uses the extended HelloBlockchainClient which provides
        convenient methods for interacting with the specific smart contract.
        The same operations could be performed using the base RestClient with
        more manual transaction construction.
    """
    # Generate two test accounts to demonstrate independent contract usage
    alice = Account.generate()
    bob = Account.generate()

    print("\n=== Addresses ===")
    print(f"Alice: {alice.address()}")
    print(f"Bob: {bob.address()}")

    # Set up clients for blockchain interaction
    rest_client = HelloBlockchainClient(NODE_URL)
    faucet_client = FaucetClient(FAUCET_URL, rest_client, FAUCET_AUTH_TOKEN)

    # Fund both accounts concurrently for efficiency
    alice_fund = faucet_client.fund_account(alice.address(), 10_000_000)
    bob_fund = faucet_client.fund_account(bob.address(), 10_000_000)
    await asyncio.gather(*[alice_fund, bob_fund])

    a_alice_balance = rest_client.account_balance(alice.address())
    a_bob_balance = rest_client.account_balance(bob.address())
    [alice_balance, bob_balance] = await asyncio.gather(
        *[a_alice_balance, a_bob_balance]
    )

    print("\n=== Initial Balances ===")
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")

    print("\n=== Testing Alice ===")
    message = await rest_client.get_message(contract_address, alice.address())
    print(f"Initial value: {message}")
    print('Setting the message to "Hello, Blockchain"')
    txn_hash = await rest_client.set_message(
        contract_address, alice, "Hello, Blockchain"
    )
    await rest_client.wait_for_transaction(txn_hash)

    message = await rest_client.get_message(contract_address, alice.address())
    print(f"New value: {message}")

    print("\n=== Testing Bob ===")
    message = await rest_client.get_message(contract_address, bob.address())
    print(f"Initial value: {message}")
    print('Setting the message to "Hello, Blockchain"')
    txn_hash = await rest_client.set_message(contract_address, bob, "Hello, Blockchain")
    await rest_client.wait_for_transaction(txn_hash)

    message = await rest_client.get_message(contract_address, bob.address())
    print(f"New value: {message}")

    await rest_client.close()


if __name__ == "__main__":
    assert len(sys.argv) == 2, "Expecting the contract address"
    contract_address = sys.argv[1]

    asyncio.run(main(AccountAddress.from_str(contract_address)))
