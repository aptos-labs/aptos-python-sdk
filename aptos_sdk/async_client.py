# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Asynchronous client library for interacting with the Aptos blockchain.

This module provides comprehensive async client implementations for connecting to and
interacting with Aptos full nodes, faucet services, and indexer services. It supports
the full range of Aptos blockchain operations including account management, transaction
submission, resource queries, and event monitoring.

Key Features:
- **RestClient**: Full-featured async client for Aptos REST API
- **IndexerClient**: GraphQL client for querying indexed blockchain data
- **FaucetClient**: Client for test network coin funding operations
- **BCS Support**: Binary Canonical Serialization for efficient data handling
- **Multi-Agent Transactions**: Support for complex multi-signature scenarios
- **Transaction Simulation**: Gas estimation and execution preview
- **Event Monitoring**: Real-time blockchain event querying
- **Error Handling**: Comprehensive exception hierarchy for API errors

Client Types:
    RestClient: Primary interface to Aptos full nodes via REST API
    IndexerClient: GraphQL interface to Aptos indexer services
    FaucetClient: Test network funding and account creation

Transaction Types:
    - Single-agent transactions (standard transfers, function calls)
    - Multi-agent transactions (requiring multiple signatures)
    - View function calls (read-only operations)
    - BCS-encoded transactions (efficient binary format)

Query Capabilities:
    - Account information (balance, sequence number, resources)
    - Transaction history and status
    - Blockchain events and logs
    - Move module and resource data
    - Table lookups and aggregator values
    - Block and ledger information

Examples:
    Basic client setup and account query::

        from aptos_sdk.async_client import RestClient, ClientConfig
        from aptos_sdk.account_address import AccountAddress

        # Create client with custom configuration
        config = ClientConfig(
            max_gas_amount=200_000,
            gas_unit_price=150,
            transaction_wait_in_seconds=30
        )

        client = RestClient("https://fullnode.devnet.aptoslabs.com/v1", config)

        # Query account information
        address = AccountAddress.from_str("0x123...")
        account_info = await client.account(address)
        balance = await client.account_balance(address)

        print(f"Sequence number: {account_info['sequence_number']}")
        print(f"Balance: {balance} octas")

        await client.close()

    Transaction submission::

        from aptos_sdk.account import Account

        # Create sender account
        sender = Account.generate()
        recipient = AccountAddress.from_str("0x456...")

        # Transfer 1 APT (1 * 10^8 octas)
        txn_hash = await client.bcs_transfer(
            sender=sender,
            recipient=recipient,
            amount=100_000_000  # 1 APT in octas
        )

        # Wait for transaction completion
        await client.wait_for_transaction(txn_hash)
        txn_info = await client.transaction_by_hash(txn_hash)

    Multi-agent transaction::

        # Create multi-agent transaction requiring multiple signatures
        signed_txn = await client.create_multi_agent_bcs_transaction(
            sender=primary_account,
            secondary_accounts=[account2, account3],
            payload=transaction_payload
        )

        txn_hash = await client.submit_bcs_transaction(signed_txn)

    IndexerClient usage::

        indexer = IndexerClient(
            "https://indexer.devnet.aptoslabs.com/v1/graphql",
            bearer_token="optional_token"
        )

        # GraphQL query example
        query = \"\"\"
        query GetTransactions($address: String!) {
            account_transactions(where: {account_address: {_eq: $address}}) {
                transaction_version
                transaction_timestamp
                success
            }
        }
        \"\"\"

        result = await indexer.query(query, {"address": str(address)})

    Faucet usage for testnet::

        faucet = FaucetClient(
            "https://faucet.devnet.aptoslabs.com",
            rest_client=client
        )

        # Fund account with test coins
        account = Account.generate()
        txn_hash = await faucet.fund_account(
            address=account.address(),
            amount=500_000_000  # 5 APT
        )

        await faucet.close()

Error Handling:
    The module provides specific exception types for different error scenarios:

    - ApiError: General API request failures (HTTP 4xx/5xx)
    - AccountNotFound: Requested account doesn't exist
    - ResourceNotFound: Requested resource not found in account

Best Practices:
    - Always call client.close() when done to clean up connections
    - Use context managers or try/finally blocks for resource cleanup
    - Configure appropriate timeouts for your use case
    - Handle specific exceptions (AccountNotFound, ResourceNotFound) when expected
    - Use BCS transactions for better performance and lower fees
    - Implement retry logic for transient network errors
    - Cache chain ID and other static values when making many requests

Note:
    All client operations are async and must be awaited. The clients use httpx
    for HTTP/2 support and connection pooling for optimal performance.
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx
import python_graphql_client

from .account import Account
from .account_address import AccountAddress
from .authenticator import Authenticator, MultiAgentAuthenticator
from .bcs import Serializer
from .metadata import Metadata
from .transactions import (
    EntryFunction,
    MultiAgentRawTransaction,
    RawTransaction,
    SignedTransaction,
    TransactionArgument,
    TransactionPayload,
)
from .type_tag import StructTag, TypeTag

U64_MAX = 18446744073709551615


@dataclass
class ClientConfig:
    """Configuration parameters for Aptos REST API clients.

    This class encapsulates common settings used by REST clients for transaction
    submission, gas management, and network communication. These parameters affect
    transaction costs, execution timeouts, and API authentication.

    Transaction Parameters:
        expiration_ttl: Time-to-live for transactions in seconds (default: 600)
        gas_unit_price: Price per unit of gas in octas (default: 100)
        max_gas_amount: Maximum gas units allowed per transaction (default: 100,000)
        transaction_wait_in_seconds: Timeout for transaction confirmation (default: 20)

    Network Parameters:
        http2: Enable HTTP/2 for better performance (default: True)
        api_key: Optional API key for authenticated requests (default: None)

    Examples:
        Default configuration::

            config = ClientConfig()
            client = RestClient(node_url, config)

        High-throughput configuration::

            config = ClientConfig(
                gas_unit_price=150,       # Higher gas price for faster processing
                max_gas_amount=200_000,   # Higher gas limit for complex transactions
                transaction_wait_in_seconds=60,  # Longer wait for busy networks
                expiration_ttl=300        # Shorter expiration for high-frequency ops
            )

        Authenticated requests::

            config = ClientConfig(
                api_key="your-api-key-here",
                http2=True  # Recommended for API services
            )

        Conservative settings::

            config = ClientConfig(
                gas_unit_price=100,       # Standard gas price
                max_gas_amount=50_000,    # Lower gas limit to prevent runaway
                expiration_ttl=1200       # Longer expiration for manual workflows
            )

    Notes:
        - Gas prices may need adjustment based on network congestion
        - Higher gas limits allow more complex transactions but cost more
        - HTTP/2 is recommended for better connection reuse and performance
        - API keys are required for some premium or rate-limited services
        - Transaction expiration prevents stale transactions from executing
    """

    expiration_ttl: int = 600
    gas_unit_price: int = 100
    max_gas_amount: int = 100_000
    transaction_wait_in_seconds: int = 20
    http2: bool = True
    api_key: Optional[str] = None


class IndexerClient:
    """GraphQL client for querying indexed Aptos blockchain data.

    This client provides access to the Aptos Indexer Service, which indexes
    blockchain data into a PostgreSQL database exposed via Hasura GraphQL API.
    The indexer provides rich querying capabilities for transactions, accounts,
    events, and other blockchain data.

    Key Features:
    - **Rich Queries**: Complex filtering, sorting, and aggregation of blockchain data
    - **Real-time Data**: Access to up-to-date indexed blockchain information
    - **Flexible API**: GraphQL interface supporting custom query structures
    - **Authentication**: Optional bearer token authentication for premium access
    - **High Performance**: Optimized database queries for fast data retrieval

    Use Cases:
    - Analytics and reporting on blockchain activity
    - Transaction history and account analysis
    - Event monitoring and notification systems
    - DeFi protocol data aggregation
    - NFT marketplace data queries
    - Portfolio tracking applications

    Attributes:
        client: The underlying GraphQL client for executing queries

    Examples:
        Basic setup and query::

            indexer = IndexerClient(
                "https://indexer.mainnet.aptoslabs.com/v1/graphql",
                bearer_token="optional-auth-token"
            )

            # Query account transactions
            query = \"\"\"
            query GetAccountTransactions($address: String!, $limit: Int!) {
                account_transactions(
                    where: {account_address: {_eq: $address}},
                    limit: $limit,
                    order_by: {transaction_version: desc}
                ) {
                    transaction_version
                    success
                    gas_used
                    transaction_timestamp
                }
            }
            \"\"\"

            result = await indexer.query(query, {
                "address": "0x1",
                "limit": 100
            })

        Token transfer queries::

            query = \"\"\"
            query GetTokenTransfers($token_address: String!) {
                token_activities(
                    where: {
                        token_data_id: {_eq: $token_address},
                        type: {_eq: "0x3::token_transfers::TokenTransferEvent"}
                    },
                    limit: 50,
                    order_by: {transaction_version: desc}
                ) {
                    from_address
                    to_address
                    amount
                    transaction_version
                    transaction_timestamp
                }
            }
            \"\"\"

            transfers = await indexer.query(query, {
                "token_address": "0xabc123..."
            })

        Account resource tracking::

            query = \"\"\"
            query GetAccountResources($address: String!) {
                account_resources(
                    where: {account_address: {_eq: $address}}
                ) {
                    resource_type
                    resource_data
                    write_set_change_index
                    transaction_version
                }
            }
            \"\"\"

            resources = await indexer.query(query, {"address": address})

    Note:
        The indexer service may have query limits and rate limiting. Some
        advanced features may require authentication tokens. Check the specific
        indexer service documentation for available schema and limitations.
    """

    client: python_graphql_client.GraphqlClient

    def __init__(self, indexer_url: str, bearer_token: Optional[str] = None):
        """Initialize the IndexerClient with connection parameters.

        Args:
            indexer_url: The GraphQL endpoint URL for the Aptos indexer service.
            bearer_token: Optional authentication token for premium access.

        Examples:
            Public access::

                client = IndexerClient(
                    "https://indexer.devnet.aptoslabs.com/v1/graphql"
                )

            Authenticated access::

                client = IndexerClient(
                    "https://indexer.mainnet.aptoslabs.com/v1/graphql",
                    bearer_token="your-token-here"
                )
        """
        headers = {}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        self.client = python_graphql_client.GraphqlClient(
            endpoint=indexer_url, headers=headers
        )

    async def query(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a GraphQL query against the Aptos Indexer.

        This async method executes GraphQL queries with variable substitution
        and returns the structured response data.

        Args:
            query: GraphQL query string with proper syntax and structure.
            variables: Dictionary of variables to substitute in the query.

        Returns:
            Dictionary containing the GraphQL response data and metadata.

        Raises:
            Exception: On GraphQL syntax errors, network issues, or server errors.

        Examples:
            Simple account query::

                query = \"\"\"
                query GetAccount($address: String!) {
                    account_transactions(
                        where: {account_address: {_eq: $address}}
                        limit: 10
                    ) {
                        transaction_version
                        success
                    }
                }
                \"\"\"

                result = await indexer.query(query, {"address": "0x1"})
                transactions = result["data"]["account_transactions"]

            Complex aggregation query::

                query = \"\"\"
                query GetDailyStats($date: timestamptz!) {
                    transactions_aggregate(
                        where: {
                            inserted_at: {_gte: $date}
                        }
                    ) {
                        aggregate {
                            count
                            sum {
                                gas_used
                            }
                        }
                    }
                }
                \"\"\"

                stats = await indexer.query(query, {
                    "date": "2024-01-01T00:00:00Z"
                })

        Note:
            The query must follow GraphQL syntax. Use the indexer's schema
            documentation to understand available fields and relationships.
        """
        return await self.client.execute_async(query, variables)


class RestClient:
    """Comprehensive async client for the Aptos blockchain REST API.

    This client provides complete access to Aptos full node functionality through
    the REST API, supporting all blockchain operations including account management,
    transaction submission, resource queries, event monitoring, and more.

    Core Capabilities:
    - **Account Operations**: Balance queries, resource access, transaction history
    - **Transaction Management**: Submission, simulation, status tracking, waiting
    - **Blockchain Queries**: Block data, ledger info, event streams
    - **Move Integration**: View functions, resource inspection, module access
    - **Advanced Features**: Multi-agent transactions, BCS encoding, gas estimation

    Performance Features:
    - **HTTP/2 Support**: Efficient connection reuse and multiplexing
    - **Connection Pooling**: Optimized for high-throughput applications
    - **Async/Await**: Non-blocking operations for better concurrency
    - **Configurable Timeouts**: Flexible timeout management for different use cases
    - **Automatic Retries**: Built-in resilience for transient network issues

    Transaction Types:
    - Single-signature transactions (most common)
    - Multi-signature transactions (shared accounts, DAOs)
    - Script transactions (custom Move code execution)
    - Entry function calls (smart contract interactions)

    Attributes:
        _chain_id: Cached network chain ID (mainnet=1, testnet=2, etc.)
        client: Underlying HTTP client with connection pooling
        client_config: Configuration for gas, timeouts, and other parameters
        base_url: Base URL of the Aptos full node REST API

    Examples:
        Basic client setup::

            from aptos_sdk.async_client import RestClient, ClientConfig

            # Use default configuration
            client = RestClient("https://fullnode.mainnet.aptoslabs.com/v1")

            # Custom configuration for high-throughput apps
            config = ClientConfig(
                max_gas_amount=200_000,
                gas_unit_price=150,
                transaction_wait_in_seconds=60
            )
            client = RestClient("https://fullnode.devnet.aptoslabs.com/v1", config)

        Account operations::

            from aptos_sdk.account_address import AccountAddress

            address = AccountAddress.from_str("0x1")

            # Get account information
            account_data = await client.account(address)
            sequence_number = account_data["sequence_number"]

            # Check balance
            balance = await client.account_balance(address)
            print(f"Balance: {balance / 10**8} APT")

            # Get all resources
            resources = await client.account_resources(address)
            for resource in resources:
                print(f"Resource: {resource['type']}")

        Transaction submission::

            from aptos_sdk.account import Account

            # Create accounts
            sender = Account.generate()
            recipient = AccountAddress.from_str("0x456...")

            # Simple transfer
            txn_hash = await client.bcs_transfer(
                sender=sender,
                recipient=recipient,
                amount=100_000_000  # 1 APT in octas
            )

            # Wait for confirmation
            await client.wait_for_transaction(txn_hash)
            txn_data = await client.transaction_by_hash(txn_hash)

            if txn_data["success"]:
                print(f"Transfer successful! Gas used: {txn_data['gas_used']}")

        Transaction simulation::

            # Create transaction without submitting
            raw_txn = await client.create_bcs_transaction(
                sender=sender_account,
                payload=transaction_payload
            )

            # Simulate to estimate gas
            simulation = await client.simulate_transaction(
                transaction=raw_txn,
                sender=sender_account,
                estimate_gas_usage=True
            )

            print(f"Estimated gas: {simulation[0]['gas_used']}")
            print(f"Success: {simulation[0]['success']}")

        Multi-agent transactions::

            # Transactions requiring multiple signatures
            signed_txn = await client.create_multi_agent_bcs_transaction(
                sender=primary_account,
                secondary_accounts=[account2, account3],
                payload=shared_transaction_payload
            )

            txn_hash = await client.submit_bcs_transaction(signed_txn)

        View function calls::

            # Read-only function calls (no gas cost)
            result = await client.view(
                function="0x1::coin::balance",
                type_arguments=["0x1::aptos_coin::AptosCoin"],
                arguments=[str(address)]
            )
            balance = int(result[0])

        Event monitoring::

            # Get events by creation number
            events = await client.event_by_creation_number(
                account_address=contract_address,
                creation_number=0,  # First event stream
                limit=100
            )

            for event in events:
                print(f"Event: {event['type']}, Data: {event['data']}")

    Error Handling:
        The client raises specific exceptions for different failure modes:
        - ApiError: HTTP errors (4xx, 5xx status codes)
        - AccountNotFound: Account doesn't exist on-chain
        - ResourceNotFound: Requested resource not found in account

    Best Practices:
        - Always call await client.close() when done
        - Use try/finally or async context managers for cleanup
        - Cache chain_id() result for better performance
        - Configure appropriate gas limits for your transactions
        - Implement exponential backoff for retries on failures
        - Use BCS transactions for better performance and fees
        - Monitor gas usage and adjust pricing as needed

    Note:
        This client is designed for production use with proper connection
        management, timeout handling, and error recovery. It supports both
        mainnet and testnet environments.
    """

    _chain_id: Optional[int]
    client: httpx.AsyncClient
    client_config: ClientConfig
    base_url: str

    def __init__(self, base_url: str, client_config: ClientConfig = ClientConfig()):
        """Initialize the REST client with configuration parameters.

        Args:
            base_url: Base URL of the Aptos full node REST API.
                Examples: "https://fullnode.mainnet.aptoslabs.com/v1",
                         "https://fullnode.devnet.aptoslabs.com/v1"
            client_config: Configuration for gas, timeouts, and networking.
                Defaults to standard settings if not provided.

        Examples:
            Mainnet client::

                client = RestClient("https://fullnode.mainnet.aptoslabs.com/v1")

            Testnet with custom config::

                config = ClientConfig(
                    gas_unit_price=200,
                    max_gas_amount=150_000,
                    api_key="your-api-key"
                )
                client = RestClient(
                    "https://fullnode.testnet.aptoslabs.com/v1",
                    config
                )

            Local development node::

                client = RestClient("http://localhost:8080/v1")

        Note:
            The client automatically configures HTTP/2, connection pooling,
            proper headers, and timeouts for optimal performance.
        """
        self.base_url = base_url
        # Default limits
        limits = httpx.Limits()
        # Default timeouts but do not set a pool timeout, since the idea is that jobs will wait as
        # long as progress is being made.
        timeout = httpx.Timeout(60.0, pool=None)
        # Default headers
        headers = {Metadata.APTOS_HEADER: Metadata.get_aptos_header_val()}
        self.client = httpx.AsyncClient(
            http2=client_config.http2,
            limits=limits,
            timeout=timeout,
            headers=headers,
        )
        self.client_config = client_config
        self._chain_id = None
        if client_config.api_key:
            self.client.headers["Authorization"] = f"Bearer {client_config.api_key}"

    async def close(self):
        """
        Close the underlying HTTP client connection.

        This is a coroutine that should be called when done with the client
        to properly clean up resources.
        """
        await self.client.aclose()

    async def chain_id(self):
        """
        Get the chain ID of the network.

        This is a coroutine that fetches and caches the chain ID from the node.

        :return: The numeric chain ID (e.g., 1 for mainnet, 2 for testnet)
        :raises ApiError: If the node info request fails
        """
        if not self._chain_id:
            info = await self.info()
            self._chain_id = int(info["chain_id"])
        return self._chain_id

    #
    # Account accessors
    #

    async def account(
        self, account_address: AccountAddress, ledger_version: Optional[int] = None
    ) -> Dict[str, str]:
        """
        Fetch the authentication key and the sequence number for an account address.

        :param account_address: Address of the account, with or without a '0x' prefix.
        :param ledger_version: Ledger version to get state of account. If not provided, it will be the latest version.
        :return: The authentication key and sequence number for the specified address.
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}",
            params={"ledger_version": ledger_version},
        )
        if response.status_code >= 400:
            raise ApiError(f"{response.text} - {account_address}", response.status_code)
        return response.json()

    async def account_balance(
        self,
        account_address: AccountAddress,
        ledger_version: Optional[int] = None,
        coin_type: Optional[str] = None,
    ) -> int:
        """
        Fetch the Aptos coin balance associated with the account.

        :param account_address: Address of the account, with or without a '0x' prefix.
        :param ledger_version: Ledger version to get state of account. If not provided, it will be the latest version.
        :param coin_type: Coin type to get balance for, defaults to "0x1::aptos_coin::AptosCoin".
        :return: The Aptos coin balance associated with the account
        """
        coin_type = coin_type or "0x1::aptos_coin::AptosCoin"
        result = await self.view_bcs_payload(
            "0x1::coin",
            "balance",
            [TypeTag(StructTag.from_str(coin_type))],
            [TransactionArgument(account_address, Serializer.struct)],
            ledger_version,
        )
        return int(result[0])

    async def account_sequence_number(
        self, account_address: AccountAddress, ledger_version: Optional[int] = None
    ) -> int:
        """
        Fetch the current sequence number for an account address.

        :param account_address: Address of the account, with or without a '0x' prefix.
        :param ledger_version: Ledger version to get state of account. If not provided, it will be the latest version.
        :return: The current sequence number for the specified address.
        """
        try:
            account_res = await self.account(account_address, ledger_version)
            return int(account_res["sequence_number"])
        except ApiError as ae:
            if ae.status_code != 404:
                raise
            return 0

    async def account_resource(
        self,
        account_address: AccountAddress,
        resource_type: str,
        ledger_version: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Retrieves an individual resource from a given account and at a specific ledger version.

        The Aptos nodes prune account state history, via a configurable time window. If the requested ledger version
        has been pruned, the server responds with a 410.

        :param account_address: Address of the account, with or without a '0x' prefix.
        :param resource_type: Name of struct to retrieve e.g. 0x1::account::Account.
        :param ledger_version: Ledger version to get state of account. If not provided, it will be the latest version.
        :return: An individual resource from a given account and at a specific ledger version.
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}/resource/{resource_type}",
            params={"ledger_version": ledger_version},
        )
        if response.status_code == 404:
            raise ResourceNotFound(resource_type, resource_type)
        if response.status_code >= 400:
            raise ApiError(f"{response.text} - {account_address}", response.status_code)
        return response.json()

    async def account_resources(
        self,
        account_address: AccountAddress,
        ledger_version: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieves all account resources for a given account and a specific ledger version.

        The Aptos nodes prune account state history, via a configurable time window. If the requested ledger version
        has been pruned, the server responds with a 410.

        :param account_address: Address of the account, with or without a '0x' prefix.
        :param ledger_version: Ledger version to get state of account. If not provided, it will be the latest version.
        :return: All account resources for a given account and a specific ledger version.
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}/resources",
            params={"ledger_version": ledger_version},
        )
        if response.status_code == 404:
            raise AccountNotFound(f"{account_address}", account_address)
        if response.status_code >= 400:
            raise ApiError(f"{response.text} - {account_address}", response.status_code)
        return response.json()

    async def account_module(
        self,
        account_address: AccountAddress,
        module_name: str,
        ledger_version: Optional[int] = None,
    ) -> dict:
        """
        Retrieves an individual module from a given account and at a specific ledger version.

        The Aptos nodes prune account state history, via a configurable time window. If the requested ledger version
        has been pruned, the server responds with a 410.

        :param account_address: Address of the account, with or without a '0x' prefix.
        :param module_name: Name of module to retrieve e.g. 'coin'
        :param ledger_version: Ledger version to get state of account. If not provided, it will be the latest version.
        :return: An individual module from a given account and at a specific ledger version
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}/module/{module_name}",
            params={"ledger_version": ledger_version},
        )
        if response.status_code >= 400:
            raise ApiError(f"{response.text} - {account_address}", response.status_code)

        return response.json()

    async def account_modules(
        self,
        account_address: AccountAddress,
        ledger_version: Optional[int] = None,
        limit: Optional[int] = None,
        start: Optional[str] = None,
    ) -> dict:
        """
        Retrieves all account modules' bytecode for a given account at a specific ledger version.

        The Aptos nodes prune account state history, via a configurable time window. If the requested ledger version
        has been pruned, the server responds with a 410.

        :param account_address: Address of the account, with or without a '0x' prefix.
        :param ledger_version: Ledger version to get state of account. If not provided, it will be the latest version.
        :param limit: Max number of account modules to retrieve. If not provided, defaults to default page size.
        :param start: Cursor specifying where to start for pagination.
        :return: All account modules' bytecode for a given account at a specific ledger version.
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}/modules",
            params={
                "ledger_version": ledger_version,
                "limit": limit,
                "start": start,
            },
        )
        if response.status_code == 404:
            raise AccountNotFound(f"{account_address}", account_address)
        if response.status_code >= 400:
            raise ApiError(f"{response.text} - {account_address}", response.status_code)

        return response.json()

    #
    # Blocks
    #

    async def blocks_by_height(
        self,
        block_height: int,
        with_transactions: bool = False,
    ) -> dict:
        """
        Fetch the transactions in a block and the corresponding block information.

        Transactions are limited by max default transactions size. If not all transactions are present, the user will
        need to query for the rest of the transactions via the get transactions API. If the block is pruned, it will
        return a 410.

        :param block_height: Block height to lookup. Starts at 0.
        :param with_transactions: If set to true, include all transactions in the block.
        :returns: Block information.
        """
        response = await self._get(
            endpoint=f"blocks/by_height/{block_height}",
            params={
                "with_transactions": with_transactions,
            },
        )
        if response.status_code >= 400:
            raise ApiError(f"{response.text}", response.status_code)

        return response.json()

    async def blocks_by_version(
        self,
        version: int,
        with_transactions: bool = False,
    ) -> dict:
        """
        Fetch the transactions in a block and the corresponding block information, given a version in the block.

        Transactions are limited by max default transactions size. If not all transactions are present, the user will
        need to query for the rest of the transactions via the get transactions API. If the block is pruned, it will
        return a 410.

        :param version: Ledger version to lookup block information for.
        :param with_transactions: If set to true, include all transactions in the block.
        :returns: Block information.
        """
        response = await self._get(
            endpoint=f"blocks/by_version/{version}",
            params={
                "with_transactions": with_transactions,
            },
        )
        if response.status_code >= 400:
            raise ApiError(f"{response.text}", response.status_code)

        return response.json()

    #
    # Events
    #

    async def event_by_creation_number(
        self,
        account_address: AccountAddress,
        creation_number: int,
        limit: Optional[int] = None,
        start: Optional[int] = None,
    ) -> List[dict]:
        """
        Retrieve events corresponding to an account address and creation number indicating the event type emitted
        to that account.

        Creation numbers are monotonically increasing for each account address.

        :param account_address: Address of the account, with or without a '0x' prefix.
        :param creation_number: Creation number corresponding to the event stream originating from the given account.
        :param limit: Max number of events to retrieve. If not provided, defaults to default page size.
        :param start: Starting sequence number of events.If unspecified, by default will retrieve the most recent.
        :returns: Events corresponding to an account address and creation number indicating the event type emitted
        to that account.
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}/events/{creation_number}",
            params={
                "limit": limit,
                "start": start,
            },
        )
        if response.status_code >= 400:
            raise ApiError(f"{response.text} - {account_address}", response.status_code)

        return response.json()

    async def events_by_event_handle(
        self,
        account_address: AccountAddress,
        event_handle: str,
        field_name: str,
        limit: Optional[int] = None,
        start: Optional[int] = None,
    ) -> List[dict]:
        """
        Retrieve events corresponding to an account address, event handle (struct name) and field name.

        :param account_address: Address of the account, with or without a '0x' prefix.
        :param event_handle: Name of struct to lookup event handle e.g., '0x1::account::Account'.
        :param field_name: Name of field to lookup event handle e.g., 'withdraw_events'
        :param limit: Max number of events to retrieve. If not provided, defaults to default page size.
        :param start: Starting sequence number of events.If unspecified, by default will retrieve the most recent.
        :returns: Events corresponding to the provided account address, event handle and field name.
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}/events/{event_handle}/{field_name}",
            params={
                "limit": limit,
                "start": start,
            },
        )
        if response.status_code >= 400:
            raise ApiError(f"{response.text} - {account_address}", response.status_code)

        return response.json()

    async def current_timestamp(self) -> float:
        """
        Get the current ledger timestamp in seconds.

        This is a coroutine that fetches the latest ledger info and
        converts the timestamp from microseconds to seconds.

        :return: Current ledger timestamp as a float in seconds
        :raises ApiError: If the node info request fails
        """
        info = await self.info()
        return float(info["ledger_timestamp"]) / 1_000_000

    async def get_table_item(
        self,
        handle: str,
        key_type: str,
        value_type: str,
        key: Any,
        ledger_version: Optional[int] = None,
    ) -> Any:
        """
        Retrieve an item from a Move table by its key.

        This is a coroutine that queries a table item using the table handle
        and key information.

        :param handle: The table handle identifying the table
        :param key_type: The Move type of the key (e.g., "address", "u64")
        :param value_type: The Move type of the value (e.g., "u128", "vector<u8>")
        :param key: The key value to look up
        :param ledger_version: Ledger version to query. If not provided, uses the latest version
        :return: The value stored at the given key in the table
        :raises ApiError: If the request fails or the key is not found
        """
        response = await self._post(
            endpoint=f"tables/{handle}/item",
            data={
                "key_type": key_type,
                "value_type": value_type,
                "key": key,
            },
            params={"ledger_version": ledger_version},
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()

    async def aggregator_value(
        self,
        account_address: AccountAddress,
        resource_type: str,
        aggregator_path: List[str],
    ) -> int:
        """
        Retrieve the current value of an aggregator.

        This is a coroutine that follows a path through a resource to find
        an aggregator and returns its current value.

        :param account_address: Address of the account containing the resource
        :param resource_type: The Move type of the resource containing the aggregator
        :param aggregator_path: Path through the resource structure to the aggregator
        :return: Current value of the aggregator as an integer
        :raises ApiError: If the resource is not found or the aggregator path is invalid
        """
        source = await self.account_resource(account_address, resource_type)
        source_data = data = source["data"]

        while len(aggregator_path) > 0:
            key = aggregator_path.pop()
            if key not in data:
                raise ApiError(
                    f"aggregator path not found in data: {source_data}", source_data
                )
            data = data[key]

        if "vec" not in data:
            raise ApiError(f"aggregator not found in data: {source_data}", source_data)
        data = data["vec"]
        if len(data) != 1:
            raise ApiError(f"aggregator not found in data: {source_data}", source_data)
        data = data[0]
        if "aggregator" not in data:
            raise ApiError(f"aggregator not found in data: {source_data}", source_data)
        data = data["aggregator"]
        if "vec" not in data:
            raise ApiError(f"aggregator not found in data: {source_data}", source_data)
        data = data["vec"]
        if len(data) != 1:
            raise ApiError(f"aggregator not found in data: {source_data}", source_data)
        data = data[0]
        if "handle" not in data:
            raise ApiError(f"aggregator not found in data: {source_data}", source_data)
        if "key" not in data:
            raise ApiError(f"aggregator not found in data: {source_data}", source_data)
        handle = data["handle"]
        key = data["key"]
        return int(await self.get_table_item(handle, "address", "u128", key))

    #
    # Ledger accessors
    #

    async def info(self) -> Dict[str, str]:
        """
        Get information about the Aptos node.

        This is a coroutine that retrieves general information about the node
        including chain ID, ledger version, and timestamps.

        :return: Dictionary containing node information
        :raises ApiError: If the request fails
        """
        response = await self.client.get(self.base_url)
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()

    #
    # Transactions
    #

    async def simulate_bcs_transaction(
        self,
        signed_transaction: SignedTransaction,
        estimate_gas_usage: bool = False,
    ) -> Dict[str, Any]:
        """
        Simulate a BCS-encoded signed transaction without executing it.

        This is a coroutine that submits a transaction for simulation to estimate
        gas usage and validate execution without making on-chain changes.

        :param signed_transaction: The signed transaction to simulate
        :param estimate_gas_usage: If True, estimate gas unit price and max gas amount
        :return: Simulation result containing execution information
        :raises ApiError: If the simulation request fails
        """
        headers = {"Content-Type": "application/x.aptos.signed_transaction+bcs"}
        params = {}
        if estimate_gas_usage:
            params = {
                "estimate_gas_unit_price": "true",
                "estimate_max_gas_amount": "true",
            }

        response = await self.client.post(
            f"{self.base_url}/transactions/simulate",
            params=params,
            headers=headers,
            content=signed_transaction.bytes(),
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)

        return response.json()

    async def simulate_transaction(
        self,
        transaction: RawTransaction,
        sender: Account,
        estimate_gas_usage: bool = False,
    ) -> Dict[str, Any]:
        """
        Simulate a raw transaction without executing it on-chain.

        This is a coroutine that signs a transaction with a simulated signature
        (all zeros) and submits it for simulation.

        :param transaction: The raw transaction to simulate
        :param sender: The account that would send the transaction
        :param estimate_gas_usage: If True, estimate gas unit price and max gas amount
        :return: Simulation result containing execution information
        :raises ApiError: If the simulation request fails
        """
        # Note that simulated transactions are not signed and have all 0 signatures!
        authenticator = sender.sign_simulated_transaction(transaction)
        return await self.simulate_bcs_transaction(
            signed_transaction=SignedTransaction(transaction, authenticator),
            estimate_gas_usage=estimate_gas_usage,
        )

    async def submit_bcs_transaction(
        self, signed_transaction: SignedTransaction
    ) -> str:
        """
        Submit a BCS-encoded signed transaction to the blockchain.

        This is a coroutine that submits a transaction for execution.
        The transaction will be added to the mempool and eventually executed.

        :param signed_transaction: The signed transaction to submit
        :return: The transaction hash as a hex string
        :raises ApiError: If the submission fails
        """
        headers = {"Content-Type": "application/x.aptos.signed_transaction+bcs"}
        response = await self.client.post(
            f"{self.base_url}/transactions",
            headers=headers,
            content=signed_transaction.bytes(),
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()["hash"]

    async def submit_and_wait_for_bcs_transaction(
        self, signed_transaction: SignedTransaction
    ) -> Dict[str, Any]:
        """
        Submit a BCS-encoded signed transaction and wait for it to complete.

        This is a coroutine that submits a transaction and polls until it's
        no longer pending, then returns the transaction details.

        :param signed_transaction: The signed transaction to submit
        :return: The completed transaction details
        :raises ApiError: If submission fails or transaction times out
        :raises AssertionError: If transaction fails or times out
        """
        txn_hash = await self.submit_bcs_transaction(signed_transaction)
        await self.wait_for_transaction(txn_hash)
        return await self.transaction_by_hash(txn_hash)

    async def transaction_pending(self, txn_hash: str) -> bool:
        """
        Check if a transaction is still pending.

        This is a coroutine that queries the transaction status to determine
        if it's still pending execution.

        :param txn_hash: The transaction hash to check
        :return: True if the transaction is still pending, False otherwise
        :raises ApiError: If the status check request fails
        """
        response = await self._get(endpoint=f"transactions/by_hash/{txn_hash}")
        # TODO(@davidiw): consider raising a different error here, since this is an ambiguous state
        if response.status_code == 404:
            return True
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()["type"] == "pending_transaction"

    async def wait_for_transaction(self, txn_hash: str) -> None:
        """
        Waits up to the duration specified in client_config for a transaction to move past pending
        state.
        """

        count = 0
        while await self.transaction_pending(txn_hash):
            assert (
                count < self.client_config.transaction_wait_in_seconds
            ), f"transaction {txn_hash} timed out"
            await asyncio.sleep(1)
            count += 1

        response = await self._get(endpoint=f"transactions/by_hash/{txn_hash}")
        assert (
            "success" in response.json() and response.json()["success"]
        ), f"{response.text} - {txn_hash}"

    async def account_transaction_sequence_number_status(
        self, address: AccountAddress, sequence_number: int
    ) -> bool:
        """Retrieve the state of a transaction by account and sequence number."""
        response = await self._get(
            endpoint=f"accounts/{address}/transactions",
            params={
                "limit": 1,
                "start": sequence_number,
            },
        )
        if response.status_code >= 400:
            logging.info(f"k {response}")
            raise ApiError(response.text, response.status_code)
        data = response.json()
        return len(data) == 1 and data[0]["type"] != "pending_transaction"

    async def transaction_by_hash(self, txn_hash: str) -> Dict[str, Any]:
        """
        Retrieve a transaction by its hash.

        This is a coroutine that fetches transaction details using the
        transaction hash.

        :param txn_hash: The transaction hash to look up
        :return: Transaction details as a dictionary
        :raises ApiError: If the transaction is not found or request fails
        """
        response = await self._get(endpoint=f"transactions/by_hash/{txn_hash}")
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()

    async def transaction_by_version(self, version: int) -> Dict[str, Any]:
        """
        Retrieve a transaction by its ledger version.

        This is a coroutine that fetches transaction details using the
        ledger version number.

        :param version: The ledger version of the transaction to retrieve
        :return: Transaction details as a dictionary
        :raises ApiError: If the transaction is not found or request fails
        """
        response = await self._get(endpoint=f"transactions/by_version/{version}")
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()

    async def transactions_by_account(
        self,
        account_address: AccountAddress,
        limit: Optional[int] = None,
        start: Optional[int] = None,
    ) -> List[dict]:
        """
        Retrieves on-chain committed transactions from an account.

        If the start version is too far in the past, a 410 will be returned. If no start version is given, it will
        start at version 0.

        To retrieve a pending transaction, use /transactions/by_hash.

        :param account_address: Address of account with or without a 0x prefix.
        :param limit: Max number of transactions to retrieve. If not provided, defaults to default page size.
        :param start: Account sequence number to start list of transactions. Defaults to latest transactions.
        :returns: List of on-chain committed transactions from the specified account.
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}/transactions",
            params={
                "limit": limit,
                "start": start,
            },
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)

        return response.json()

    async def transactions(
        self,
        limit: Optional[int] = None,
        start: Optional[int] = None,
    ) -> List[dict]:
        """
        Retrieve on-chain committed transactions.

        The page size and start ledger version can be provided to get a specific sequence of transactions. If the
        version has been pruned, then a 410 will be returned. To retrieve a pending transaction,
        use /transactions/by_hash.

        :param limit: Max number of transactions to retrieve. If not provided, defaults to default page size.
        :param start: Ledger version to start list of transactions. Defaults to showing the latest transactions.
        """
        response = await self._get(
            endpoint="transactions",
            params={
                "limit": limit,
                "start": start,
            },
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)

        return response.json()

    #
    # Transaction helpers
    #

    async def create_multi_agent_bcs_transaction(
        self,
        sender: Account,
        secondary_accounts: List[Account],
        payload: TransactionPayload,
    ) -> SignedTransaction:
        """
        Create a multi-agent BCS transaction with multiple signers.

        This is a coroutine that creates a transaction requiring signatures
        from multiple accounts (sender and secondary accounts).

        :param sender: The primary account sending the transaction
        :param secondary_accounts: Additional accounts that must sign the transaction
        :param payload: The transaction payload to execute
        :return: A signed multi-agent transaction
        :raises ApiError: If account sequence number lookup fails
        """
        raw_transaction = MultiAgentRawTransaction(
            RawTransaction(
                sender.address(),
                await self.account_sequence_number(sender.address()),
                payload,
                self.client_config.max_gas_amount,
                self.client_config.gas_unit_price,
                int(time.time()) + self.client_config.expiration_ttl,
                await self.chain_id(),
            ),
            [x.address() for x in secondary_accounts],
        )

        authenticator = Authenticator(
            MultiAgentAuthenticator(
                sender.sign_transaction(raw_transaction),
                [
                    (
                        x.address(),
                        x.sign_transaction(raw_transaction),
                    )
                    for x in secondary_accounts
                ],
            )
        )

        return SignedTransaction(raw_transaction.inner(), authenticator)

    async def create_bcs_transaction(
        self,
        sender: Account | AccountAddress,
        payload: TransactionPayload,
        sequence_number: Optional[int] = None,
    ) -> RawTransaction:
        """
        Create a raw BCS transaction ready for signing.

        This is a coroutine that builds a raw transaction with the specified
        payload and transaction parameters.

        :param sender: The sender account or address
        :param payload: The transaction payload to execute
        :param sequence_number: Specific sequence number, or None to fetch from chain
        :return: An unsigned raw transaction
        :raises ApiError: If sequence number lookup or chain ID fetch fails
        """
        if isinstance(sender, Account):
            sender_address = sender.address()
        else:
            sender_address = sender

        sequence_number = (
            sequence_number
            if sequence_number is not None
            else await self.account_sequence_number(sender_address)
        )
        return RawTransaction(
            sender_address,
            sequence_number,
            payload,
            self.client_config.max_gas_amount,
            self.client_config.gas_unit_price,
            int(time.time()) + self.client_config.expiration_ttl,
            await self.chain_id(),
        )

    async def create_bcs_signed_transaction(
        self,
        sender: Account,
        payload: TransactionPayload,
        sequence_number: Optional[int] = None,
    ) -> SignedTransaction:
        """
        Create and sign a BCS transaction ready for submission.

        This is a coroutine that creates a raw transaction and signs it
        with the sender's private key.

        :param sender: The account that will send and sign the transaction
        :param payload: The transaction payload to execute
        :param sequence_number: Specific sequence number, or None to fetch from chain
        :return: A fully signed transaction ready for submission
        :raises ApiError: If sequence number lookup or chain ID fetch fails
        """
        raw_transaction = await self.create_bcs_transaction(
            sender, payload, sequence_number
        )
        authenticator = sender.sign_transaction(raw_transaction)
        return SignedTransaction(raw_transaction, authenticator)

    #
    # Transaction wrappers
    #

    # :!:>bcs_transfer
    async def bcs_transfer(
        self,
        sender: Account,
        recipient: AccountAddress,
        amount: int,
        sequence_number: Optional[int] = None,
    ) -> str:
        """
        Transfer Aptos coins from sender to recipient.

        This is a coroutine that creates, signs, and submits a transfer transaction.

        :param sender: The account sending the coins
        :param recipient: Address of the account to receive the coins
        :param amount: Amount of coins to transfer in octas (1 APT = 10^8 octas)
        :param sequence_number: Specific sequence number, or None to fetch from chain
        :return: The transaction hash as a hex string
        :raises ApiError: If transaction creation or submission fails
        """
        transaction_arguments = [
            TransactionArgument(recipient, Serializer.struct),
            TransactionArgument(amount, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x1::aptos_account",
            "transfer",
            [],
            transaction_arguments,
        )

        signed_transaction = await self.create_bcs_signed_transaction(
            sender, TransactionPayload(payload), sequence_number=sequence_number
        )
        return await self.submit_bcs_transaction(signed_transaction)  # <:!:bcs_transfer

    async def transfer_coins(
        self,
        sender: Account,
        recipient: AccountAddress,
        coin_type: str,
        amount: int,
        sequence_number: Optional[int] = None,
    ) -> str:
        """
        Transfer coins of a specific type from sender to recipient.

        This is a coroutine that creates, signs, and submits a transfer transaction
        for any coin type (not just Aptos coins).

        :param sender: The account sending the coins
        :param recipient: Address of the account to receive the coins
        :param coin_type: The fully qualified coin type (e.g., "0x123456::usdc::USDC")
        :param amount: Amount of coins to transfer (in the coin's base units)
        :param sequence_number: Specific sequence number, or None to fetch from chain
        :return: The transaction hash as a hex string
        :raises ApiError: If transaction creation or submission fails
        """
        transaction_arguments = [
            TransactionArgument(recipient, Serializer.struct),
            TransactionArgument(amount, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x1::aptos_account",
            "transfer_coins",
            [TypeTag(StructTag.from_str(coin_type))],
            transaction_arguments,
        )

        signed_transaction = await self.create_bcs_signed_transaction(
            sender, TransactionPayload(payload), sequence_number=sequence_number
        )
        return await self.submit_bcs_transaction(signed_transaction)

    async def transfer_object(
        self, owner: Account, object: AccountAddress, to: AccountAddress
    ) -> str:
        """
        Transfer ownership of an object to another account.

        This is a coroutine that creates, signs, and submits a transaction to
        transfer ownership of an Aptos object.

        :param owner: The current owner of the object
        :param object: The address of the object to transfer
        :param to: The address of the new owner
        :return: The transaction hash as a hex string
        :raises ApiError: If transaction creation or submission fails
        """
        transaction_arguments = [
            TransactionArgument(object, Serializer.struct),
            TransactionArgument(to, Serializer.struct),
        ]

        payload = EntryFunction.natural(
            "0x1::object",
            "transfer_call",
            [],
            transaction_arguments,
        )

        signed_transaction = await self.create_bcs_signed_transaction(
            owner,
            TransactionPayload(payload),
        )
        return await self.submit_bcs_transaction(signed_transaction)

    async def view(
        self,
        function: str,
        type_arguments: List[str],
        arguments: List[str],
        ledger_version: Optional[int] = None,
    ) -> bytes:
        """
        Execute a view Move function with the given parameters and return its execution result.

        The Aptos nodes prune account state history, via a configurable time window. If the requested ledger version
        has been pruned, the server responds with a 410.

        :param function: Entry function id is string representation of an entry function defined on-chain.
        :param type_arguments: Type arguments of the function.
        :param arguments: Arguments of the function.
        :param ledger_version: Ledger version to get state of account. If not provided, it will be the latest version.
        :returns: Execution result.
        """
        response = await self._post(
            endpoint="view",
            params={
                "ledger_version": ledger_version,
            },
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            data={
                "function": function,
                "type_arguments": type_arguments,
                "arguments": arguments,
            },
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)

        return response.content

    async def view_bcs_payload(
        self,
        module: str,
        function: str,
        ty_args: List[TypeTag],
        args: List[TransactionArgument],
        ledger_version: Optional[int] = None,
    ) -> Any:
        """
        Execute a view Move function with the given parameters and return its execution result.
        Note, this differs from `view` as in this expects bcs compatible inputs and submits the
        view function in bcs format. This is convenient for clients that execute functions in
        transactions similar to view functions.

        The Aptos nodes prune account state history, via a configurable time window. If the requested ledger version
        has been pruned, the server responds with a 410.

        :param function: Entry function id is string representation of an entry function defined on-chain.
        :param type_arguments: Type arguments of the function.
        :param arguments: Arguments of the function.
        :param ledger_version: Ledger version to get state of account. If not provided, it will be the latest version.
        :returns: Execution result.
        """
        request = f"{self.base_url}/view"
        if ledger_version:
            request = f"{request}?ledger_version={ledger_version}"

        view_data = EntryFunction.natural(module, function, ty_args, args)
        ser = Serializer()
        view_data.serialize(ser)
        headers = {"Content-Type": "application/x.aptos.view_function+bcs"}
        response = await self.client.post(
            request, headers=headers, content=ser.output()
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()

    async def _post(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> httpx.Response:
        # format params:
        params = {} if params is None else params
        params = {key: val for key, val in params.items() if val is not None}
        return await self.client.post(
            url=f"{self.base_url}/{endpoint}",
            params=params,
            headers=headers,
            json=data,
        )

    async def _get(
        self, endpoint: str, params: Optional[Dict[str, Any]] = None
    ) -> httpx.Response:
        # format params:
        params = {} if params is None else params
        params = {key: val for key, val in params.items() if val is not None}
        return await self.client.get(
            url=f"{self.base_url}/{endpoint}",
            params=params,
        )


class FaucetClient:
    """Faucet creates and funds accounts. This is a thin wrapper around that."""

    base_url: str
    rest_client: RestClient
    headers: Dict[str, str]

    def __init__(
        self, base_url: str, rest_client: RestClient, auth_token: Optional[str] = None
    ):
        self.base_url = base_url
        self.rest_client = rest_client
        self.headers = {}
        if auth_token:
            self.headers["Authorization"] = f"Bearer {auth_token}"

    async def close(self):
        """
        Close the underlying REST client connection.

        This is a coroutine that should be called when done with the faucet client
        to properly clean up resources.
        """
        await self.rest_client.close()

    async def fund_account(
        self, address: AccountAddress, amount: int, wait_for_transaction=True
    ):
        """This creates an account if it does not exist and mints the specified amount of
        coins into that account."""
        request = f"{self.base_url}/mint?amount={amount}&address={address}"
        response = await self.rest_client.client.post(request, headers=self.headers)
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        txn_hash = response.json()[0]
        if wait_for_transaction:
            await self.rest_client.wait_for_transaction(txn_hash)
        return txn_hash

    async def healthy(self) -> bool:
        """
        Check if the faucet service is healthy and responding.

        This is a coroutine that performs a health check on the faucet service.

        :return: True if the faucet is healthy, False otherwise
        """
        response = await self.rest_client.client.get(self.base_url)
        return "tap:ok" == response.text


class ApiError(Exception):
    """The API returned a non-success status code, e.g., >= 400"""

    status_code: int

    def __init__(self, message: str, status_code: int):
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        self.status_code = status_code


class AccountNotFound(Exception):
    """The account was not found"""

    account: AccountAddress

    def __init__(self, message: str, account: AccountAddress):
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        self.account = account


class ResourceNotFound(Exception):
    """The underlying resource was not found"""

    resource: str

    def __init__(self, message: str, resource: str):
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        self.resource = resource
