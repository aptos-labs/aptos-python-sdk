"""
Aptos Python SDK Examples - Comprehensive tutorials and sample code.

This package contains example scripts and tutorials demonstrating how to use
the Aptos Python SDK for various blockchain operations. The examples are
designed to be educational and serve as starting points for developers
building applications on the Aptos blockchain.

Example Categories:

    **Basic Operations**:
    - hello_blockchain.py: Complete smart contract deployment and interaction
    - fee_payer_transfer_coin.py: Sponsored transaction demonstrations
    - common.py: Shared configuration and utilities
    
    **Token Management**:
    - aptos_token.py: NFT creation and management using Token Objects
    
    **Advanced Features**:
    - multisig.py: Multi-signature transaction handling
    - multikey.py: Multi-key authentication examples
    - large_package_publisher.py: Publishing large Move packages
    
    **Testing and Integration**:
    - integration_test.py: Comprehensive SDK testing suite

Quick Start:
    Most examples can be run directly from the command line::
    
        # Basic blockchain interaction
        python -m examples.hello_blockchain ***contract_address***
        
        # NFT operations
        python -m examples.aptos_token
        
        # Multi-signature transactions
        python -m examples.multisig
        
    Or imported and used programmatically::
    
        import asyncio
        from examples.hello_blockchain import main, publish_contract
        
        async def run_example():
            contract_addr = await publish_contract("./my_contract")
            await main(contract_addr)
            
        asyncio.run(run_example())

Configuration:
    All examples use environment variables for network configuration.
    See examples.common for details on customizing endpoints::
    
        import os
        # Switch to testnet
        os.environ["APTOS_NODE_URL"] = "https://api.testnet.aptoslabs.com/v1"
        os.environ["APTOS_FAUCET_URL"] = "https://faucet.testnet.aptoslabs.com"
        
        # Now run any example
        from examples import hello_blockchain

Prerequisites:
    - Python 3.8+ with asyncio support
    - Aptos CLI installed (for Move compilation)
    - Network connectivity to Aptos nodes
    - For mainnet: real APT tokens for transaction fees

Learning Path:
    1. **Start with hello_blockchain.py** - covers the basics of account
       management, contract deployment, and blockchain interaction
    2. **Explore aptos_token.py** - learn NFT creation and token operations
    3. **Try fee_payer_transfer_coin.py** - understand sponsored transactions
    4. **Advanced examples** - multisig, multikey for complex scenarios

Safety:
    - All examples default to devnet for safety
    - Private keys are generated randomly and not persisted
    - No real value transactions unless explicitly configured for mainnet
    - Smart contracts are deployed to test networks only

Support:
    - Each example includes comprehensive documentation
    - Error handling examples and troubleshooting guides
    - Comments explain Aptos-specific concepts and patterns
    - Links to relevant Aptos documentation and resources

Note:
    These examples are for educational purposes. Production applications
    should implement additional security measures, error handling, and
    testing appropriate for their specific use cases.
"""
