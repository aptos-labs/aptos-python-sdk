# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Command-line interface utilities for the Aptos Python SDK.

This module provides a CLI framework for common Aptos blockchain operations,
particularly focused on Move package development and deployment. It integrates
with the Aptos CLI for compilation and provides high-level abstractions for
complex operations like package publishing.

Key Features:
- **Package Publishing**: End-to-end Move package compilation and deployment
- **Named Address Resolution**: Support for parameterized Move modules
- **Account Management**: Private key loading and account initialization
- **Network Configuration**: Flexible REST API endpoint specification
- **Error Handling**: Comprehensive validation and error reporting
- **CLI Integration**: Seamless integration with the official Aptos CLI

Supported Commands:
- publish-package: Compile and deploy Move packages to the blockchain

Use Cases:
- Move smart contract deployment workflows
- Automated deployment scripts and CI/CD integration
- Development environment setup and testing
- Multi-network deployment (devnet, testnet, mainnet)
- Package publishing with complex address configurations

Examples:
    Basic package publishing::
    
        python -m aptos_sdk.cli publish-package \
            --package-dir ./my-move-package \
            --account ***1234... \
            --private-key-path ./private_key.txt \
            --rest-api https://fullnode.devnet.aptoslabs.com/v1
            
    Package with named addresses::
    
        python -m aptos_sdk.cli publish-package \
            --package-dir ./my-move-package \
            --account ***1234... \
            --private-key-path ./private_key.txt \
            --rest-api https://fullnode.devnet.aptoslabs.com/v1 \
            --named-address my_addr=***5678... \
            --named-address other_addr=***9abc...
            
    Programmatic usage::
    
        import asyncio
        from aptos_sdk.cli import main
        
        # Run CLI command programmatically
        await main([
            'publish-package',
            '--package-dir', './my-package',
            '--account', '***1234...',
            '--private-key-path', './key.txt',
            '--rest-api', 'https://fullnode.devnet.aptoslabs.com/v1'
        ])
        
    Integration with scripts::
    
        from aptos_sdk.cli import publish_package
        from aptos_sdk.account import Account
        from aptos_sdk.account_address import AccountAddress
        from aptos_sdk.ed25519 import PrivateKey
        
        # Direct function call
        private_key = PrivateKey.from_str("ed25519-priv-...")
        account = Account(AccountAddress.from_str("***123..."), private_key)
        
        await publish_package(
            package_dir="./my-package",
            named_addresses={"MyModule": AccountAddress.from_str("***456...")},
            signer=account,
            rest_api="https://fullnode.devnet.aptoslabs.com/v1"
        )

Requirements:
    - Aptos CLI installed and available in PATH or specified via APTOS_CLI_PATH
    - Valid Move package with Move.toml configuration
    - Private key file in supported format (Ed25519)
    - Network connectivity to Aptos REST API endpoint

File Format Requirements:
    Private Key File: Should contain a single line with the private key in
    Ed25519 format, either as raw hex or AIP-80 compliant string.
    
    Move Package: Must have proper Move.toml configuration file with
    dependencies and named addresses properly specified.

Error Handling:
    The CLI provides comprehensive error checking for:
    - Missing required arguments
    - Invalid private key formats
    - Missing Aptos CLI installation
    - Network connectivity issues
    - Move compilation errors
    - Package publishing failures

Note:
    This CLI is designed for development and deployment workflows.
    For production use, consider implementing additional security measures
    for private key handling and validation.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Dict, List, Tuple

from .account import Account
from .account_address import AccountAddress
from .aptos_cli_wrapper import AptosCLIWrapper
from .async_client import RestClient
from .ed25519 import PrivateKey
from .package_publisher import PackagePublisher


async def publish_package(
    package_dir: str,
    named_addresses: Dict[str, AccountAddress],
    signer: Account,
    rest_api: str,
):
    """Compile and publish a Move package to the Aptos blockchain.
    
    This function orchestrates the complete package publishing workflow:
    1. Compiles the Move package using the Aptos CLI
    2. Creates a REST client connection to the specified network
    3. Publishes the compiled package to the blockchain
    
    Args:
        package_dir: Path to the Move package directory containing Move.toml.
        named_addresses: Dictionary mapping named address identifiers to
            their resolved AccountAddress values.
        signer: Account that will sign and pay for the package publication.
        rest_api: URL of the Aptos REST API endpoint to publish to.
        
    Raises:
        Exception: If the Move package compilation fails.
        ApiError: If the package publication transaction fails.
        FileNotFoundError: If the package directory or files don't exist.
        
    Examples:
        Basic package publishing::
        
            from aptos_sdk.account import Account
            from aptos_sdk.account_address import AccountAddress
            from aptos_sdk.ed25519 import PrivateKey
            
            # Create account from private key
            private_key = PrivateKey.from_str("ed25519-priv-...")
            account = Account(AccountAddress.from_str("***123..."), private_key)
            
            # Publish package
            await publish_package(
                package_dir="./my-move-package",
                named_addresses={},
                signer=account,
                rest_api="https://fullnode.devnet.aptoslabs.com/v1"
            )
            
        Package with named addresses::
        
            named_addresses = {
                "MyContract": AccountAddress.from_str("***456..."),
                "Treasury": AccountAddress.from_str("***789...")
            }
            
            await publish_package(
                package_dir="./complex-package",
                named_addresses=named_addresses,
                signer=deployer_account,
                rest_api="https://fullnode.mainnet.aptoslabs.com/v1"
            )
    
    Note:
        - Requires the Aptos CLI to be installed and available
        - The signer account must have sufficient APT to pay for gas
        - Package compilation output will be stored in the package directory
        - Named addresses must match those declared in Move.toml
    """
    AptosCLIWrapper.compile_package(package_dir, named_addresses)

    rest_client = RestClient(rest_api)
    publisher = PackagePublisher(rest_client)
    await publisher.publish_package_in_path(signer, package_dir)


def key_value(indata: str) -> Tuple[str, AccountAddress]:
    """Parse a named address string into name and AccountAddress components.
    
    This function parses command-line named address arguments in the format
    "name=address" and returns a tuple suitable for use in named address
    dictionaries.
    
    Args:
        indata: String in format "name=address" where address can be any
            valid AccountAddress format (hex string, shortened address, etc.)
            
    Returns:
        Tuple of (name, AccountAddress) where name is the identifier and
        AccountAddress is the parsed address object.
        
    Raises:
        ValueError: If the input string is not in the expected "name=address" format.
        Exception: If the address portion cannot be parsed as a valid AccountAddress.
        
    Examples:
        Parse named address::
        
            >>> name, addr = key_value("MyContract=***1234...")
            >>> print(f"Name: {name}, Address: {addr}")
            Name: MyContract, Address: ***1234...
            
        Multiple named addresses::
        
            named_pairs = [
                key_value("TokenContract=***1111..."),
                key_value("Treasury=***2222..."),
                key_value("Admin=***3333...")
            ]
            
            # Convert to dictionary
            named_addresses = dict(named_pairs)
            
    Command-line usage::
    
        --named-address MyContract=***1234... \
        --named-address Treasury=***5678...
        
    Note:
        This function is primarily used by the argument parser to convert
        command-line string arguments into structured data for Move compilation.
    """
    split_indata = indata.split("=")
    if len(split_indata) != 2:
        raise ValueError("Invalid named-address, expected name=account address")
    name = split_indata[0]
    account_address = AccountAddress.from_str(split_indata[1])
    return (name, account_address)


async def main(args: List[str]):
    """Main entry point for the Aptos Python SDK CLI.
    
    This function sets up the argument parser, validates inputs, and dispatches
    to the appropriate command handlers. It provides comprehensive error checking
    and user-friendly error messages.
    
    Args:
        args: List of command-line arguments (typically from sys.argv[1:])
        
    Raises:
        SystemExit: On invalid arguments, missing requirements, or command failure.
        
    Examples:
        Run from command line::
        
            python -m aptos_sdk.cli publish-package \
                --package-dir ./my-package \
                --account ***1234... \
                --private-key-path ./key.txt \
                --rest-api https://fullnode.devnet.aptoslabs.com/v1
                
        Run programmatically::
        
            import asyncio
            from aptos_sdk.cli import main
            
            await main([
                'publish-package',
                '--package-dir', './package',
                '--account', '***1234...',
                '--private-key-path', './key.txt',
                '--rest-api', 'https://fullnode.devnet.aptoslabs.com/v1',
                '--named-address', 'MyAddr=***5678...'
            ])
            
    Supported Commands:
        publish-package: Compile and deploy a Move package
        
    Required Arguments (for publish-package):
        --account: Account address that will publish the package
        --package-dir: Path to Move package directory
        --private-key-path: Path to private key file
        --rest-api: Aptos REST API endpoint URL
        
    Optional Arguments:
        --named-address: Named address mappings (can be specified multiple times)
        
    Environment Variables:
        APTOS_CLI_PATH: Path to Aptos CLI executable (if not in PATH)
        
    Note:
        The function performs extensive validation before executing commands
        to provide clear error messages for common configuration issues.
    """
    parser = argparse.ArgumentParser(description="Aptos Python CLI")
    parser.add_argument(
        "command", type=str, help="The command to execute", choices=["publish-package"]
    )
    parser.add_argument(
        "--account",
        help="The account address that will sign and publish the package",
        type=AccountAddress.from_str,
    )
    parser.add_argument(
        "--named-address",
        help="Named address mapping in format 'name=address' (can be specified multiple times)",
        nargs="*",
        type=key_value,
        default=[],
    )
    parser.add_argument(
        "--package-dir", 
        help="Path to the Move package directory containing Move.toml", 
        type=str
    )
    parser.add_argument(
        "--private-key-path", 
        help="Path to file containing the signer's private key", 
        type=str
    )
    parser.add_argument(
        "--rest-api",
        help="Aptos REST API endpoint URL (e.g., https://fullnode.devnet.aptoslabs.com/v1)",
        type=str,
    )
    parsed_args = parser.parse_args(args)

    if parsed_args.command == "publish-package":
        # Validate required arguments
        if parsed_args.account is None:
            parser.error("Missing required argument '--account'")
        if parsed_args.package_dir is None:
            parser.error("Missing required argument '--package-dir'")
        if parsed_args.rest_api is None:
            parser.error("Missing required argument '--rest-api'")
        if parsed_args.private_key_path is None:
            parser.error("Missing required argument '--private-key-path'")

        # Check for Aptos CLI availability
        if not AptosCLIWrapper.does_cli_exist():
            parser.error(
                "Missing Aptos CLI. Please install it or export its path to APTOS_CLI_PATH environment variable."
            )

        # Load private key from file
        try:
            with open(parsed_args.private_key_path) as f:
                private_key = PrivateKey.from_str(f.read().strip())
        except FileNotFoundError:
            parser.error(f"Private key file not found: {parsed_args.private_key_path}")
        except Exception as e:
            parser.error(f"Failed to load private key: {e}")

        # Create account and execute command
        account = Account(parsed_args.account, private_key)
        await publish_package(
            parsed_args.package_dir,
            dict(parsed_args.named_address),
            account,
            parsed_args.rest_api,
        )


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:]))
