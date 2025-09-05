# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Aptos Python SDK - A comprehensive Python client library for the Aptos blockchain.

The Aptos Python SDK provides a complete toolkit for interacting with the Aptos
blockchain network, including transaction submission, account management, smart
contract deployment, and blockchain data querying. It supports both synchronous
and asynchronous programming patterns.

Core Features:
- **Account Management**: Create, manage, and authenticate blockchain accounts
- **Transaction Processing**: Submit, sign, and track blockchain transactions
- **Smart Contracts**: Deploy and interact with Move smart contracts
- **REST API Client**: Full-featured REST API client with async support
- **Token Operations**: Native and custom token management (APT, NFTs)
- **Cryptographic Support**: Ed25519, Secp256k1, and multi-key authentication
- **BCS Serialization**: Binary Canonical Serialization for efficient data encoding
- **CLI Integration**: Python wrapper for the official Aptos CLI

Supported Networks:
- **Mainnet**: Production Aptos blockchain network
- **Testnet**: Public testing environment
- **Devnet**: Development and experimental features
- **Local Testnet**: Local development environment

Architecture:
- **Async-First**: Built with asyncio for high-performance applications
- **Type Safety**: Full type hints and mypy compatibility
- **Modular Design**: Import only the components you need
- **Standards Compliant**: Follows Aptos network protocols and standards
- **Cross-Platform**: Works on Linux, macOS, and Windows

Quick Start:
    Basic account and transaction operations::
    
        import asyncio
        from aptos_sdk.async_client import FaucetClient, RestClient
        from aptos_sdk.account import Account
        
        async def main():
            # Connect to Aptos devnet
            rest_client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")
            faucet_client = FaucetClient(
                "https://faucet.devnet.aptoslabs.com", 
                rest_client
            )
            
            # Create accounts
            alice = Account.generate()
            bob = Account.generate()
            
            # Fund accounts from faucet
            await faucet_client.fund_account(alice.address(), 100_000_000)
            await faucet_client.fund_account(bob.address(), 0)
            
            # Transfer APT tokens
            transaction_hash = await rest_client.transfer(
                alice, bob.address(), 1_000_000
            )
            
            # Wait for transaction completion
            result = await rest_client.wait_for_transaction(transaction_hash)
            print(f"Transaction successful: {result['success']}")
            
            await rest_client.close()
        
        asyncio.run(main())
        
    Smart contract deployment::
    
        from aptos_sdk.package_publisher import PackagePublisher
        from aptos_sdk.account_address import AccountAddress
        
        # Compile and publish a Move package
        publisher = PackagePublisher(rest_client)
        
        package_metadata, package_code = publisher.compile_package(
            package_dir="./my_move_package",
            named_addresses={
                "my_module": alice.address()
            }
        )
        
        # Deploy the package
        txn_hash = await publisher.publish_package(
            alice, package_metadata, package_code
        )
        
    Token operations::
    
        from aptos_sdk.aptos_token_client import AptosTokenClient
        
        # Create NFT collection and tokens
        token_client = AptosTokenClient(rest_client)
        
        # Create collection
        collection_name = "My NFT Collection"
        await token_client.create_collection(
            alice,
            collection_name,
            "A collection of unique NFTs",
            "https://example.com/collection.json"
        )
        
        # Mint NFT
        await token_client.create_token(
            alice,
            collection_name,
            "My First NFT",
            "A unique digital asset",
            1,  # supply
            "https://example.com/token.json"
        )

Module Organization:
    Core Modules:
    - **account**: Account creation, management, and key handling
    - **async_client**: Async REST and Faucet clients for network communication
    - **transactions**: Transaction building, signing, and submission
    - **authenticator**: Multi-signature and authentication schemes
    - **bcs**: Binary Canonical Serialization utilities
    - **account_address**: Blockchain address handling and validation
    
    Cryptography:
    - **ed25519**: Ed25519 digital signature implementation
    - **secp256k1_ecdsa**: Secp256k1 ECDSA signature support
    - **asymmetric_crypto**: Unified cryptographic interface
    
    High-Level Clients:
    - **aptos_token_client**: NFT and token creation/management
    - **package_publisher**: Move package compilation and deployment
    - **transaction_worker**: High-throughput transaction processing
    
    Development Tools:
    - **aptos_cli_wrapper**: Python wrapper for Aptos CLI
    - **type_tag**: Move type system utilities
    - **metadata**: SDK version and HTTP header management

Configuration:
    Environment Variables:
    - **APTOS_CLI_PATH**: Custom path to Aptos CLI binary
    - **APTOS_PROFILE**: Default network profile for CLI operations
    
    Network Endpoints:
    - **Mainnet**: https://fullnode.mainnet.aptoslabs.com/v1
    - **Testnet**: https://fullnode.testnet.aptoslabs.com/v1
    - **Devnet**: https://fullnode.devnet.aptoslabs.com/v1

Development:
    Running tests::
    
        # Install development dependencies
        pip install -e ".[dev]"
        
        # Run unit tests
        python -m pytest tests/
        
        # Run integration tests (requires network access)
        python -m pytest tests/integration/
        
    Local testnet::
    
        from aptos_sdk.aptos_cli_wrapper import AptosCLIWrapper
        
        # Start local testnet for development
        testnet = AptosCLIWrapper.start_node()
        is_ready = await testnet.wait_until_operational()
        
        if is_ready:
            # Use local endpoints:
            # REST: http://127.0.0.1:8080/v1
            # Faucet: http://127.0.0.1:8081
            pass
        
        # Cleanup when done
        testnet.stop()

Requirements:
    - Python 3.8 or higher
    - httpx for HTTP requests  
    - cryptography for Ed25519/Secp256k1 support
    - pynacl for additional cryptographic operations
    - Aptos CLI (for local development and Move compilation)

Security Considerations:
    - **Private Keys**: Never log or expose private keys in production
    - **Network Validation**: Always verify transaction results on-chain
    - **Rate Limiting**: Respect API rate limits and implement backoff strategies
    - **Testnet Only**: Use testnet/devnet for development and testing
    - **Package Verification**: Verify Move package bytecode before deployment

Support:
    - **Documentation**: https://aptos.dev/sdks/python-sdk/
    - **GitHub**: https://github.com/aptos-labs/aptos-python-sdk
    - **Discord**: https://discord.gg/aptoslabs
    - **Forum**: https://forum.aptoslabs.com/

License:
    Apache License 2.0
    
Note:
    This SDK is actively maintained by Aptos Labs and the community.
    For production use, always use the latest stable version and follow
    security best practices for key management and transaction handling.
"""
