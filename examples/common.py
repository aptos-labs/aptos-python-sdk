# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Common configuration and utilities for Aptos Python SDK examples.

This module provides shared constants and configuration settings used across
all example scripts in the Aptos Python SDK. It centralizes network endpoints,
authentication settings, and file paths to ensure consistency and easy
configuration management.

Key Features:
- **Environment-Based Configuration**: All settings can be overridden via environment variables
- **Multi-Network Support**: Supports devnet, testnet, and mainnet configurations
- **Development Flexibility**: Easy switching between different Aptos networks
- **Authentication Management**: Centralized faucet authentication handling

Environment Variables:
    APTOS_CORE_PATH: Path to the aptos-core repository for development
    APTOS_FAUCET_URL: URL of the Aptos faucet service for funding accounts
    FAUCET_AUTH_TOKEN: Authentication token for faucet requests (if required)
    APTOS_INDEXER_URL: URL of the Aptos GraphQL indexer service
    APTOS_NODE_URL: URL of the Aptos REST API node endpoint

Network Configurations:
    Devnet (Default):
    - Node: https://api.devnet.aptoslabs.com/v1
    - Faucet: https://faucet.devnet.aptoslabs.com
    - Indexer: https://api.devnet.aptoslabs.com/v1/graphql
    
    Testnet:
    - Node: https://api.testnet.aptoslabs.com/v1
    - Faucet: https://faucet.testnet.aptoslabs.com
    - Indexer: https://api.testnet.aptoslabs.com/v1/graphql
    
    Mainnet:
    - Node: https://api.mainnet.aptoslabs.com/v1
    - Faucet: N/A (no public faucet on mainnet)
    - Indexer: https://api.mainnet.aptoslabs.com/v1/graphql

Usage Examples:
    Using default devnet configuration::
    
        from examples.common import NODE_URL, FAUCET_URL
        from aptos_sdk.async_client import RestClient, FaucetClient
        
        # Connect to devnet by default
        rest_client = RestClient(NODE_URL)
        faucet_client = FaucetClient(FAUCET_URL, rest_client)
        
    Switching to testnet::
    
        import os
        os.environ["APTOS_NODE_URL"] = "https://api.testnet.aptoslabs.com/v1"
        os.environ["APTOS_FAUCET_URL"] = "https://faucet.testnet.aptoslabs.com"
        
        # Now imports will use testnet URLs
        from examples.common import NODE_URL, FAUCET_URL
        
    Using with authentication token::
    
        import os
        os.environ["FAUCET_AUTH_TOKEN"] = "your_faucet_token_here"
        
        from examples.common import FAUCET_URL, FAUCET_AUTH_TOKEN
        from aptos_sdk.async_client import FaucetClient, RestClient
        
        rest_client = RestClient(NODE_URL)
        faucet_client = FaucetClient(FAUCET_URL, rest_client, FAUCET_AUTH_TOKEN)
        
    Development with local aptos-core::
    
        import os
        os.environ["APTOS_CORE_PATH"] = "/path/to/your/aptos-core"
        
        from examples.common import APTOS_CORE_PATH
        # Use APTOS_CORE_PATH for local Move package compilation

Note:
    - All examples default to devnet for safety and ease of use
    - Mainnet usage requires real APT tokens and careful consideration
    - Faucet authentication tokens may be required for some networks
    - The indexer URL is used for GraphQL queries and advanced data access
"""

import os
import os.path

# Path to the aptos-core repository for local development
# Used for accessing Move examples and local blockchain setup
APTOS_CORE_PATH = os.getenv(
    "APTOS_CORE_PATH",
    os.path.abspath("./aptos-core"),
)

# :!:>section_1
# Network Configuration - All can be overridden via environment variables

# Aptos faucet service URL for funding test accounts
# Default: Devnet faucet (provides free APT tokens for testing)
FAUCET_URL = os.getenv(
    "APTOS_FAUCET_URL",
    "https://faucet.devnet.aptoslabs.com",
)

# Optional authentication token for faucet requests
# Required for some faucet configurations or rate limit increases
FAUCET_AUTH_TOKEN = os.getenv("FAUCET_AUTH_TOKEN")

# Aptos GraphQL indexer service URL for advanced queries
# Provides indexed blockchain data with powerful query capabilities
INDEXER_URL = os.getenv(
    "APTOS_INDEXER_URL",
    "https://api.devnet.aptoslabs.com/v1/graphql",
)

# Aptos REST API node endpoint URL
# Primary interface for blockchain interactions (transactions, queries, etc.)
NODE_URL = os.getenv("APTOS_NODE_URL", "https://api.devnet.aptoslabs.com/v1")
# <:!:section_1
