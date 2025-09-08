# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Basic Coin Transfer Example - Fundamental APT token operations on Aptos.

This example demonstrates the core functionality of the Aptos Python SDK by showing
how to perform basic APT coin transfers between accounts. It covers account creation,
funding from the faucet, balance checking, and executing transfers using the BCS
(Binary Canonical Serialization) format for optimal performance.

Key Concepts Demonstrated:
- **Account Generation**: Create new Aptos accounts programmatically
- **Faucet Integration**: Fund test accounts with APT tokens
- **Balance Queries**: Check account balances before and after transactions
- **BCS Transfers**: Efficient binary-encoded transaction format
- **Transaction Confirmation**: Wait for transaction completion
- **Indexer Queries**: Optional GraphQL-based transaction history lookup

Workflow:
    1. **Setup Phase**: Initialize clients and generate test accounts
    2. **Funding Phase**: Fund accounts from the devnet faucet
    3. **Transfer Phase**: Execute multiple APT transfers between accounts
    4. **Verification Phase**: Verify balance changes after each transfer
    5. **History Phase**: Query transaction history using the indexer (optional)

Transaction Details:
    - **Transfer Method**: BCS format for efficiency and lower gas costs
    - **Gas Handling**: Automatic gas fee calculation and deduction
    - **Confirmation**: Synchronous waiting for blockchain confirmation
    - **Atomicity**: Transactions are atomic (all-or-nothing execution)

Balance Tracking:
    The example tracks balances at multiple points to show transaction effects:
    - Initial balances after faucet funding
    - Intermediate balances after first transfer
    - Final balances after second transfer

Examples:
    Run the basic transfer example::

        python -m examples.transfer_coin

    Expected output shows:
    - Account addresses for Alice and Bob
    - Initial balances (Alice: 100,000,000 octas, Bob: 1 octa)
    - Balance changes after each 1,000 octa transfer
    - Transaction history from indexer (if available)

    Programmatic usage::

        import asyncio
        from examples.transfer_coin import main

        # Run the transfer example
        asyncio.run(main())

    Custom network configuration::

        import os
        # Switch to testnet
        os.environ["APTOS_NODE_URL"] = "https://api.testnet.aptoslabs.com/v1"
        os.environ["APTOS_FAUCET_URL"] = "https://faucet.testnet.aptoslabs.com"

        # Run on testnet
        python -m examples.transfer_coin

APT Token Details:
    - **Unit**: APT tokens are measured in "octas" (1 APT = 100,000,000 octas)
    - **Precision**: 8 decimal places (similar to Bitcoin's satoshis)
    - **Gas**: Transaction fees are paid in APT and deducted automatically
    - **Type**: APT is represented as "***::aptos_coin::AptosCoin" on-chain

Indexer Integration:
    If an indexer URL is configured, the example demonstrates:
    - GraphQL query construction for transaction history
    - Account-specific transaction filtering
    - Coin activity tracking including amounts and timestamps
    - Data structure navigation for complex query results

Gas Economics:
    - **Transfer Cost**: ~20-50 gas units for basic APT transfers
    - **Gas Price**: Configurable, defaults to 100 octas per gas unit
    - **Total Fee**: Typically 2,000-5,000 octas per transfer (~$0.001 USD)
    - **Faucet Funding**: Devnet provides 100 APT free for testing

Error Scenarios:
    Common issues and solutions:
    - **Insufficient Balance**: Ensure sender has enough APT for amount + gas
    - **Network Issues**: Check NODE_URL connectivity and faucet availability
    - **Invalid Addresses**: Verify account addresses are properly formatted
    - **Sequence Numbers**: SDK handles sequence number management automatically

Best Practices:
    - Always close REST clients to prevent resource leaks
    - Use BCS transfers for better performance vs JSON transactions
    - Check balances before large transfers to avoid failures
    - Handle network errors with appropriate retry logic
    - Use testnet/devnet for development, never mainnet for examples

Learning Objectives:
    After running this example, you should understand:
    1. How to create and fund Aptos accounts for testing
    2. How to check account balances and track changes
    3. How to perform APT transfers using the Python SDK
    4. How transaction confirmation works on Aptos
    5. How to query transaction history using the indexer
    6. The relationship between APT tokens, octas, and gas fees

Note:
    This example uses devnet by default, which is safe for experimentation.
    All accounts and transactions are on the test network with no real value.
"""

import asyncio

from aptos_sdk.account import Account
from aptos_sdk.async_client import FaucetClient, IndexerClient, RestClient

from .common import FAUCET_AUTH_TOKEN, FAUCET_URL, INDEXER_URL, NODE_URL


async def main():
    """Execute the basic APT coin transfer demonstration.

    This function demonstrates the fundamental workflow for transferring APT tokens
    between accounts on the Aptos blockchain. It showcases account generation,
    faucet funding, balance tracking, and transaction execution using the most
    efficient BCS (Binary Canonical Serialization) format.

    The demo performs the following operations:
    1. **Client Setup**: Initialize REST, Faucet, and optional Indexer clients
    2. **Account Creation**: Generate Alice and Bob accounts with new key pairs
    3. **Funding**: Fund Alice with 100 APT and Bob with minimal balance (1 octa)
    4. **First Transfer**: Alice sends 1,000 octas to Bob
    5. **Second Transfer**: Alice sends another 1,000 octas to Bob
    6. **Balance Verification**: Track balance changes throughout the process
    7. **History Query**: Optional indexer query for transaction history
    8. **Cleanup**: Close all network connections properly

    Transaction Flow:
        Initial State:
        - Alice: 100,000,000 octas (100 APT from faucet)
        - Bob: 1 octa (minimal funding from faucet)

        After First Transfer (1,000 octas):
        - Alice: ~99,997,000 octas (100 APT - 1,000 - gas fees)
        - Bob: 1,001 octas (1 + 1,000 received)

        After Second Transfer (1,000 octas):
        - Alice: ~99,994,000 octas (previous - 1,000 - gas fees)
        - Bob: 2,001 octas (previous + 1,000 received)

    Technical Details:
        - **Transfer Method**: Uses `bcs_transfer()` for optimal performance
        - **Gas Management**: Automatic gas calculation and payment from sender
        - **Confirmation**: Synchronous waiting ensures transaction completion
        - **Error Handling**: Network operations may raise ApiError exceptions
        - **Balance Precision**: All amounts in octas (1 APT = 100,000,000 octas)

    Indexer Integration:
        If INDEXER_URL is configured, the function demonstrates:
        - GraphQL query construction for transaction history
        - Account-specific filtering using Bob's address
        - Coin activity data extraction (amounts, types, timestamps)
        - Assertion validation that transactions were recorded

    Expected Output::

        === Addresses ===
        Alice: ***abc123...
        Bob: ***def456...

        === Initial Balances ===
        Alice: 100000000
        Bob: 1

        === Intermediate Balances ===
        Alice: 99997000  # Approximate after gas fees
        Bob: 1001

        === Final Balances ===
        Alice: 99994000  # Approximate after second transfer
        Bob: 2001

    Error Scenarios:
        - **Network Connectivity**: REST API or faucet unavailable
        - **Insufficient Funds**: Alice doesn't have enough for transfer + gas
        - **Invalid Configuration**: Malformed URLs in environment variables
        - **Indexer Issues**: GraphQL queries may fail if indexer is down

    Performance Notes:
        - **BCS Format**: More efficient than JSON transactions (~30% gas savings)
        - **Concurrent Operations**: Uses asyncio.gather for parallel balance queries
        - **Connection Pooling**: REST client reuses connections for efficiency
        - **Minimal Funding**: Bob gets only 1 octa to show exact transfer amounts

    Network Requirements:
        - Active internet connection
        - Access to Aptos devnet endpoints
        - Faucet service availability for account funding
        - Optional: Indexer service for transaction history queries

    Raises:
        ApiError: For network communication failures or blockchain errors
        Exception: For general application errors or configuration issues

    Note:
        This function is designed to be educational and uses devnet exclusively.
        All transactions are on test networks with no real monetary value.
    """
    # Initialize clients for blockchain interaction
    # :!:>section_1
    rest_client = RestClient(NODE_URL)
    faucet_client = FaucetClient(
        FAUCET_URL, rest_client, FAUCET_AUTH_TOKEN
    )  # <:!:section_1

    # Optional indexer client for transaction history queries
    if INDEXER_URL and INDEXER_URL != "none":
        indexer_client = IndexerClient(INDEXER_URL)
    else:
        indexer_client = None

    # :!:>section_2
    alice = Account.generate()
    bob = Account.generate()  # <:!:section_2

    print("\n=== Addresses ===")
    print(f"Alice: {alice.address()}")
    print(f"Bob: {bob.address()}")

    # :!:>section_3
    alice_fund = faucet_client.fund_account(alice.address(), 100_000_000)
    bob_fund = faucet_client.fund_account(bob.address(), 1)  # <:!:section_3
    await asyncio.gather(*[alice_fund, bob_fund])

    print("\n=== Initial Balances ===")
    # :!:>section_4
    alice_balance = rest_client.account_balance(alice.address())
    bob_balance = rest_client.account_balance(bob.address())
    [alice_balance, bob_balance] = await asyncio.gather(*[alice_balance, bob_balance])
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")  # <:!:section_4

    # Have Alice give Bob 1_000 coins
    # :!:>section_5
    txn_hash = await rest_client.bcs_transfer(
        alice, bob.address(), 1_000
    )  # <:!:section_5
    # :!:>section_6
    await rest_client.wait_for_transaction(txn_hash)  # <:!:section_6

    print("\n=== Intermediate Balances ===")
    alice_balance = rest_client.account_balance(alice.address())
    bob_balance = rest_client.account_balance(bob.address())
    [alice_balance, bob_balance] = await asyncio.gather(*[alice_balance, bob_balance])
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")  # <:!:section_4

    # Have Alice give Bob another 1_000 coins using BCS
    txn_hash = await rest_client.bcs_transfer(alice, bob.address(), 1_000)
    await rest_client.wait_for_transaction(txn_hash)

    print("\n=== Final Balances ===")
    alice_balance = rest_client.account_balance(alice.address())
    bob_balance = rest_client.account_balance(bob.address())
    [alice_balance, bob_balance] = await asyncio.gather(*[alice_balance, bob_balance])
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")

    if indexer_client:
        query = """
            query TransactionsQuery($account: String) {
              account_transactions(
                limit: 20
                where: {account_address: {_eq: $account}}
              ) {
                transaction_version
                coin_activities {
                  amount
                  activity_type
                  coin_type
                  entry_function_id_str
                  owner_address
                  transaction_timestamp
                }
              }
            }
        """

        variables = {"account": f"{bob.address()}"}
        data = await indexer_client.query(query, variables)
        assert len(data["data"]["account_transactions"]) > 0

    await rest_client.close()


if __name__ == "__main__":
    asyncio.run(main())
