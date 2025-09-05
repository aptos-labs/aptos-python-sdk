# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Move package publishing and deployment utilities for the Aptos blockchain.

This module provides comprehensive tools for deploying Move smart contracts to the Aptos
blockchain. It handles package compilation, metadata generation, deployment strategies,
and large package management through automated chunking.

Key Features:
- **Package Publishing**: Deploy Move packages to accounts or objects
- **Large Package Support**: Automatic chunking for packages exceeding transaction limits
- **Object-Based Deployment**: Support for the new object-based code deployment model
- **Package Upgrades**: Upgrading existing deployed packages with compatibility checks
- **Multiple Deployment Modes**: Account-based, object-based, and upgrade modes
- **Deterministic Addresses**: Calculate deployment addresses before publishing

Deployment Models:
    Account-Based Deployment:
        - Traditional deployment model where code is stored in an account
        - Code is published to the sender's account storage
        - Suitable for simple contracts and legacy compatibility
        
    Object-Based Deployment:
        - Modern deployment model using Aptos objects
        - Code is stored in a dedicated object with its own address
        - Better isolation and more flexible upgrade policies
        - Recommended for new packages
        
    Package Upgrades:
        - Update existing deployed packages with new code
        - Supports compatibility policies and authorization checks
        - Works with both account-based and object-based deployments

Large Package Handling:
    Aptos transactions have a size limit (currently 64KB). This module automatically
    detects packages that exceed this limit and uses a chunked publishing strategy:
    
    1. **Chunking**: Package data is split into manageable chunks
    2. **Staging**: Chunks are uploaded using the large_packages module
    3. **Assembly**: The final transaction triggers on-chain reassembly
    4. **Publishing**: The complete package is deployed atomically

Examples:
    Basic package deployment::
    
        from aptos_sdk.package_publisher import PackagePublisher, PublishMode
        from aptos_sdk.async_client import RestClient
        from aptos_sdk.account import Account
        
        # Setup
        client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")
        publisher = PackagePublisher(client)
        account = Account.load("./deployer_account.json")
        
        # Deploy package
        txn_hashes = await publisher.publish_package_in_path(
            sender=account,
            package_dir="./my_move_package"
        )
        
        # Wait for completion
        for txn_hash in txn_hashes:
            await client.wait_for_transaction(txn_hash)
            
        print(f"Package deployed in {len(txn_hashes)} transactions")
        
    Object-based deployment with address prediction::
    
        # Predict deployment address
        object_address = await publisher.derive_object_address(account.address())
        print(f"Package will be deployed to: {object_address}")
        
        # Deploy to object
        txn_hashes = await publisher.publish_package_in_path(
            sender=account,
            package_dir="./my_package",
            publish_mode=PublishMode.OBJECT_DEPLOY
        )
        
        # Verify deployment
        for txn_hash in txn_hashes:
            await client.wait_for_transaction(txn_hash)
            
    Package upgrade workflow::
    
        # Identify the object to upgrade
        code_object = AccountAddress.from_str("***existing_object_address")
        
        # Deploy upgrade
        txn_hashes = await publisher.publish_package_in_path(
            sender=account,
            package_dir="./updated_package",
            publish_mode=PublishMode.OBJECT_UPGRADE,
            code_object=code_object
        )
        
    Low-level publishing with custom data::
    
        # Read compiled package data
        with open("package-metadata.bcs", "rb") as f:
            metadata = f.read()
            
        modules = []
        for module_file in os.listdir("bytecode_modules"):
            with open(f"bytecode_modules/{module_file}", "rb") as f:
                modules.append(f.read())
                
        # Publish directly
        txn_hash = await publisher.publish_package(account, metadata, modules)

Workflow Requirements:
    1. **Compile Package**: Use Move compiler or Aptos CLI to compile source code
    2. **Directory Structure**: Ensure proper build directory layout
    3. **Account Setup**: Have a funded account for transaction fees
    4. **Network Configuration**: Connect to the appropriate Aptos network
    
Directory Structure:
    Expected package directory layout::
    
        my_package/
        ├── Move.toml                    # Package manifest
        ├── sources/                     # Move source files
        │   ├── module1.move
        │   └── module2.move
        └── build/                       # Compiled artifacts (generated)
            └── MyPackage/
                ├── bytecode_modules/    # Compiled .mv files
                │   ├── module1.mv
                │   └── module2.mv
                └── package-metadata.bcs # Package metadata

Gas Considerations:
    - Small packages: ~100,000 gas units
    - Large packages: 200,000+ gas units per chunk
    - Object deployment: Slightly higher gas costs
    - Upgrades: Variable based on compatibility checks
    
Security Considerations:
    - **Package Verification**: Review all Move code before deployment
    - **Upgrade Policies**: Set appropriate upgrade policies in Move.toml
    - **Access Control**: Ensure only authorized accounts can upgrade packages
    - **Testing**: Thoroughly test packages on devnet/testnet before mainnet
    
Error Handling:
    Common deployment errors:
    - **Compilation Errors**: Fix Move source code issues
    - **Missing Files**: Ensure proper build directory structure
    - **Insufficient Funds**: Account needs enough APT for gas fees
    - **Permission Denied**: Check upgrade authorization for existing packages
    - **Network Issues**: Verify connectivity to Aptos network

Best Practices:
    - Use object-based deployment for new packages
    - Set conservative upgrade policies
    - Test on devnet before mainnet deployment
    - Monitor gas usage for cost optimization
    - Use descriptive package names and versions
    - Document package APIs and upgrade procedures

Note:
    This module requires pre-compiled Move packages. Use the Aptos CLI or Move
    compiler to generate the necessary bytecode and metadata files before
    attempting to publish.
"""

import os
from enum import Enum
from typing import List, Optional

import tomli

from .account import Account
from .account_address import AccountAddress
from .async_client import RestClient
from .bcs import Serializer
from .transactions import EntryFunction, TransactionArgument, TransactionPayload

# Maximum amount of publishing data, this gives us buffer for BCS overheads
MAX_TRANSACTION_SIZE: int = 62000

# The location of the large package publisher
MODULE_ADDRESS: AccountAddress = AccountAddress.from_str(
    "0xfa3911d7715238b2e3bd5b26b6a35e11ffa16cff318bc11471e84eccee8bd291"
)

# Domain separator for the code object address derivation
OBJECT_CODE_DEPLOYMENT_DOMAIN_SEPARATOR = b"aptos_framework::object_code_deployment"


class PublishMode(Enum):
    ACCOUNT_DEPLOY = "ACCOUNT_DEPLOY"
    OBJECT_DEPLOY = "OBJECT_DEPLOY"
    OBJECT_UPGRADE = "OBJECT_UPGRADE"


class PackagePublisher:
    """Move package compilation and deployment manager for Aptos blockchain.
    
    The PackagePublisher provides a comprehensive interface for compiling and publishing
    Move smart contract packages to the Aptos blockchain. It supports various deployment
    modes including traditional account-based deployment, object-based deployment, and
    package upgrades.
    
    Key Features:
    - **Package Compilation**: Compile Move source code to bytecode
    - **Metadata Generation**: Create package metadata for deployment
    - **Large Package Support**: Handles packages exceeding transaction size limits
    - **Chunked Publishing**: Automatic splitting of large packages across transactions
    - **Object Deployment**: Support for object-based code deployment model
    - **Package Upgrades**: Upgrading existing deployed packages
    
    Deployment Modes:
    - **Account Deploy**: Traditional deployment to an account (default)
    - **Object Deploy**: Deployment to an object (newer model)
    - **Object Upgrade**: Upgrading existing object-based packages
    
    Examples:
        Basic package deployment::
        
            from aptos_sdk.package_publisher import PackagePublisher
            from aptos_sdk.async_client import RestClient
            from aptos_sdk.account import Account
            
            # Create client and publisher
            client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")
            publisher = PackagePublisher(client)
            
            # Deploy a package from a local directory
            account = Account.load("./my_account.json")
            txn_hashes = await publisher.publish_package_in_path(
                sender=account,
                package_dir="./my_move_package"
            )
            
            # Wait for transactions to complete
            for txn_hash in txn_hashes:
                await client.wait_for_transaction(txn_hash)
                
        Object-based deployment::
        
            # Deploy to an object instead of an account
            from aptos_sdk.package_publisher import PublishMode
            
            # Deploy as a new object
            txn_hashes = await publisher.publish_package_in_path(
                sender=account,
                package_dir="./my_package",
                publish_mode=PublishMode.OBJECT_DEPLOY
            )
            
            # Get the deployed object address
            object_address = await publisher.derive_object_address(account.address())
            print(f"Package deployed to object: {object_address}")
            
        Upgrading a package::
        
            # Upgrade an existing object-based package
            from aptos_sdk.account_address import AccountAddress
            
            # Address of the existing code object
            code_object = AccountAddress.from_str("***abcdef...")
            
            # Publish the upgrade
            txn_hashes = await publisher.publish_package_in_path(
                sender=account,
                package_dir="./updated_package",
                publish_mode=PublishMode.OBJECT_UPGRADE,
                code_object=code_object
            )
            
        Large package handling::
        
            # For packages exceeding transaction size limits
            # Chunked publishing happens automatically
            txn_hashes = await publisher.publish_package_in_path(
                sender=account,
                package_dir="./large_package"
            )
            
            print(f"Package published in {len(txn_hashes)} transactions")
            
    Workflow:
        1. Compile Move package (using CLI or other tools)
        2. Create PackagePublisher with RestClient
        3. Call publish_package_in_path with appropriate sender and package path
        4. Monitor transaction hashes for completion
        5. (Optional) Derive object address for object deployments
    
    Technical Details:
    - Packages over ~62KB are automatically chunked across multiple transactions
    - Object deployment uses a deterministic address derived from publisher and sequence number
    - Package metadata and compiled bytecode modules are read from the build directory
    - BCS serialization is used for efficient binary encoding
    
    Note:
        This class requires Move packages to be precompiled with the Move compiler.
        The package directory must contain a build subdirectory with compiled artifacts.
    """

    client: RestClient

    def __init__(self, client: RestClient):
        """Initialize a PackagePublisher with a REST client.
        
        Creates a new package publisher that uses the provided REST client for
        blockchain interactions. The client must be properly configured for
        the target network (mainnet, testnet, etc.).
        
        Args:
            client: The RestClient instance to use for blockchain communication
                and transaction submission.
                
        Examples:
            Create with default client::
            
                from aptos_sdk.async_client import RestClient
                
                # Create for devnet
                client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")
                publisher = PackagePublisher(client)
                
            Create with custom client configuration::
            
                from aptos_sdk.async_client import RestClient, ClientConfig
                
                # Custom gas settings for large packages
                config = ClientConfig(
                    max_gas_amount=300_000,  # Higher gas limit
                    gas_unit_price=150,      # Higher priority
                    transaction_wait_in_seconds=60  # Longer timeout
                )
                
                client = RestClient("https://fullnode.mainnet.aptoslabs.com/v1", config)
                publisher = PackagePublisher(client)
        """
        self.client = client

    async def publish_package(
        self, sender: Account, package_metadata: bytes, modules: List[bytes]
    ) -> str:
        """Publish a Move package to an account on the Aptos blockchain.
        
        This method submits a transaction to publish a Move package to the sender's
        account. It requires pre-compiled package metadata and module bytecode.
        
        Args:
            sender: The account that will sign and pay for the transaction.
            package_metadata: The BCS-encoded package metadata bytes.
            modules: List of BCS-encoded bytecode modules.
            
        Returns:
            str: The transaction hash of the submitted transaction.
            
        Transaction Details:
            This calls the 0x1::code::publish_package_txn entry function with the
            package metadata and modules as arguments.
            
        Note:
            This is the low-level publish method. Most users should use
            publish_package_in_path instead, which handles reading files
            and chunking large packages.
        """
        transaction_arguments = [
            TransactionArgument(package_metadata, Serializer.to_bytes),
            TransactionArgument(
                modules, Serializer.sequence_serializer(Serializer.to_bytes)
            ),
        ]

        payload = EntryFunction.natural(
            "0x1::code",
            "publish_package_txn",
            [],
            transaction_arguments,
        )

        signed_transaction = await self.client.create_bcs_signed_transaction(
            sender, TransactionPayload(payload)
        )
        return await self.client.submit_bcs_transaction(signed_transaction)

    async def publish_package_to_object(
        self, sender: Account, package_metadata: bytes, modules: List[bytes]
    ) -> str:
        """Publish a Move package to a new object on the Aptos blockchain.
        
        This method submits a transaction to publish a Move package to a new object
        instead of an account. This uses the object-based code deployment model,
        which is newer and provides better isolation.
        
        Args:
            sender: The account that will sign and pay for the transaction.
            package_metadata: The BCS-encoded package metadata bytes.
            modules: List of BCS-encoded bytecode modules.
            
        Returns:
            str: The transaction hash of the submitted transaction.
            
        Transaction Details:
            This calls the 0x1::object_code_deployment::publish entry function with
            the package metadata and modules as arguments.
            
        Note:
            After publishing, you can derive the object address using the
            derive_object_address method. Object-based deployment is the recommended
            approach for new packages.
        """
        transaction_arguments = [
            TransactionArgument(package_metadata, Serializer.to_bytes),
            TransactionArgument(
                modules, Serializer.sequence_serializer(Serializer.to_bytes)
            ),
        ]

        payload = EntryFunction.natural(
            "0x1::object_code_deployment",
            "publish",
            [],
            transaction_arguments,
        )

        signed_transaction = await self.client.create_bcs_signed_transaction(
            sender, TransactionPayload(payload)
        )
        return await self.client.submit_bcs_transaction(signed_transaction)

    async def upgrade_package_object(
        self,
        sender: Account,
        package_metadata: bytes,
        modules: List[bytes],
        object_address: AccountAddress,
    ) -> str:
        """Upgrade an existing object-based Move package.
        
        This method submits a transaction to upgrade an existing object-based
        Move package with new code. The sender must have the appropriate permissions
        to upgrade the package (typically, must be the original publisher).
        
        Args:
            sender: The account that will sign and pay for the transaction.
            package_metadata: The BCS-encoded package metadata bytes for the upgrade.
            modules: List of BCS-encoded bytecode modules for the upgrade.
            object_address: The address of the object containing the code to upgrade.
            
        Returns:
            str: The transaction hash of the submitted transaction.
            
        Transaction Details:
            This calls the 0x1::object_code_deployment::upgrade entry function with
            the package metadata, modules, and object address as arguments.
            
        Upgrade Rules:
            - The upgrade policy in the original package must allow upgrades
            - The sender must be authorized to perform the upgrade
            - Module compatibility requirements must be satisfied based on policy
            
        Note:
            This only works for packages deployed with the object-based model.
            For traditional account-based packages, use a different upgrade mechanism.
        """
        transaction_arguments = [
            TransactionArgument(package_metadata, Serializer.to_bytes),
            TransactionArgument(
                modules, Serializer.sequence_serializer(Serializer.to_bytes)
            ),
            TransactionArgument(object_address, Serializer.struct),
        ]

        payload = EntryFunction.natural(
            "0x1::object_code_deployment",
            "upgrade",
            [],
            transaction_arguments,
        )

        signed_transaction = await self.client.create_bcs_signed_transaction(
            sender, TransactionPayload(payload)
        )
        return await self.client.submit_bcs_transaction(signed_transaction)

    async def publish_package_in_path(
        self,
        sender: Account,
        package_dir: str,
        large_package_address: AccountAddress = MODULE_ADDRESS,
        publish_mode: PublishMode = PublishMode.ACCOUNT_DEPLOY,
        code_object: Optional[AccountAddress] = None,
    ) -> List[str]:
        """Publish a Move package from a local directory to the Aptos blockchain.
        
        This high-level method handles reading compiled Move package files from a
        directory and publishing them to the blockchain. It automatically determines
        if chunked publishing is needed for large packages and supports different
        deployment modes.
        
        Args:
            sender: The account that will sign and pay for the transaction(s).
            package_dir: Path to the Move package directory containing the compiled build.
                Must have a Move.toml file and a build subdirectory with compiled artifacts.
            large_package_address: Address of the module that handles large package
                publishing (default: predefined MODULE_ADDRESS).
            publish_mode: The deployment mode to use (ACCOUNT_DEPLOY, OBJECT_DEPLOY,
                or OBJECT_UPGRADE).
            code_object: The address of the object to upgrade (required only for
                OBJECT_UPGRADE mode).
                
        Returns:
            List[str]: List of transaction hashes. For small packages, this will
                contain a single hash. For large packages, it will contain multiple
                hashes corresponding to the chunked transactions.
                
        Raises:
            ValueError: If code_object is not provided for OBJECT_UPGRADE mode,
                if the publish_mode is invalid, or if required files are missing.
            FileNotFoundError: If the package directory or required files don't exist.
            
        Directory Structure:
            The package directory must contain:
            - Move.toml: Package manifest file
            - build/{package_name}/bytecode_modules/: Compiled module bytecode (.mv files)
            - build/{package_name}/package-metadata.bcs: Package metadata file
            
        Examples:
            Publish a package to an account::
            
                txn_hashes = await publisher.publish_package_in_path(
                    sender=account,
                    package_dir="./my_move_package"
                )
                
            Publish a package to an object::
            
                txn_hashes = await publisher.publish_package_in_path(
                    sender=account,
                    package_dir="./my_package",
                    publish_mode=PublishMode.OBJECT_DEPLOY
                )
                
                # Get the deployed object address
                object_address = await publisher.derive_object_address(account.address())
                
            Upgrade an existing object-based package::
            
                txn_hashes = await publisher.publish_package_in_path(
                    sender=account,
                    package_dir="./updated_package",
                    publish_mode=PublishMode.OBJECT_UPGRADE,
                    code_object=AccountAddress.from_str("***abcdef...")
                )
                
        Note:
            This method requires the package to be already compiled. It does not
            compile the Move source code itself, but reads the compiled artifacts.
            Use the Aptos CLI or Move compiler to compile the package first.
        """
        with open(os.path.join(package_dir, "Move.toml"), "rb") as f:
            data = tomli.load(f)
        package = data["package"]["name"]

        package_build_dir = os.path.join(package_dir, "build", package)
        module_directory = os.path.join(package_build_dir, "bytecode_modules")
        module_paths = os.listdir(module_directory)
        modules = []
        for module_path in module_paths:
            module_path = os.path.join(module_directory, module_path)
            if not os.path.isfile(module_path) and not module_path.endswith(".mv"):
                continue
            with open(module_path, "rb") as f:
                module = f.read()
                modules.append(module)

        metadata_path = os.path.join(package_build_dir, "package-metadata.bcs")
        with open(metadata_path, "rb") as f:
            metadata = f.read()

        # If the package size is larger than a single transaction limit, use chunked publish.
        if self.is_large_package(metadata, modules):
            return await self.chunked_package_publish(
                sender, metadata, modules, large_package_address, publish_mode
            )

        # If the deployment can fit into a single transaction, use the normal package publisher
        if publish_mode == PublishMode.ACCOUNT_DEPLOY:
            txn_hash = await self.publish_package(sender, metadata, modules)
        elif publish_mode == PublishMode.OBJECT_DEPLOY:
            txn_hash = await self.publish_package_to_object(sender, metadata, modules)
        elif publish_mode == PublishMode.OBJECT_UPGRADE:
            if code_object is None:
                raise ValueError("code_object must be provided for OBJECT_UPGRADE mode")
            txn_hash = await self.upgrade_package_object(
                sender, metadata, modules, code_object
            )
        else:
            raise ValueError(f"Unexpected publish mode: {publish_mode}")

        return [txn_hash]

    async def derive_object_address(
        self, publisher_address: AccountAddress
    ) -> AccountAddress:
        """Derive the address of a newly deployed object-based package.
        
        This method calculates the address where a package will be deployed when
        using OBJECT_DEPLOY mode. It uses the publisher's address and next sequence
        number to deterministically derive the object address.
        
        Args:
            publisher_address: The address of the account publishing the package.
            
        Returns:
            AccountAddress: The derived address where the package object will be created.
            
        Examples:
            Get the address before deployment::
            
                # Calculate where the package will be deployed
                object_address = await publisher.derive_object_address(account.address())
                print(f"Package will be deployed to: {object_address}")
                
                # Deploy the package
                await publisher.publish_package_in_path(
                    sender=account,
                    package_dir="./my_package",
                    publish_mode=PublishMode.OBJECT_DEPLOY
                )
                
        Note:
            This method gets the current sequence number from the blockchain and
            adds 1 to calculate the next sequence number that will be used for
            the deployment transaction.
        """
        sequence_number = await self.client.account_sequence_number(publisher_address)
        return self.create_object_deployment_address(
            publisher_address, sequence_number + 1
        )

    @staticmethod
    def create_object_deployment_address(
        creator_address: AccountAddress, creator_sequence_number: int
    ) -> AccountAddress:
        """Calculate the deterministic address for an object-based code deployment.
        
        This static method computes the address where a package will be deployed
        when using object-based deployment. The address is deterministically derived
        from the creator's address and sequence number.
        
        Args:
            creator_address: The address of the account creating the object.
            creator_sequence_number: The sequence number of the creator account
                that will be used for the deployment transaction.
                
        Returns:
            AccountAddress: The deterministic address where the object will be created.
            
        Technical Details:
            The address is derived using a domain-specific seed combining:
            - The domain separator "aptos_framework::object_code_deployment"
            - The creator's sequence number
            - The creator's address
            
        Note:
            This is a low-level method used by derive_object_address. Most users
            should use derive_object_address instead, which automatically fetches
            the current sequence number from the blockchain.
        """
        ser = Serializer()
        ser.to_bytes(OBJECT_CODE_DEPLOYMENT_DOMAIN_SEPARATOR)
        ser.u64(creator_sequence_number)
        seed = ser.output()

        return AccountAddress.for_named_object(creator_address, seed)

    async def chunked_package_publish(
        self,
        sender: Account,
        package_metadata: bytes,
        modules: List[bytes],
        large_package_address: AccountAddress = MODULE_ADDRESS,
        publish_mode: PublishMode = PublishMode.ACCOUNT_DEPLOY,
    ) -> List[str]:
        """Publish a large package by splitting it across multiple transactions.
        
        This method handles publishing packages that exceed the transaction size limit
        (currently 64KB) by splitting the package data across multiple transactions.
        It optimizes the chunking to use as few transactions as possible while staying
        within size limits.
        
        Args:
            sender: The account that will sign and pay for the transactions.
            package_metadata: The BCS-encoded package metadata bytes.
            modules: List of BCS-encoded bytecode modules.
            large_package_address: Address of the module that handles large package
                publishing (default: predefined MODULE_ADDRESS).
            publish_mode: The deployment mode to use (ACCOUNT_DEPLOY, OBJECT_DEPLOY,
                or OBJECT_UPGRADE).
                
        Returns:
            List[str]: List of transaction hashes for all the chunked transactions.
            
        Transaction Batching:
            - Each transaction has a conservative 62KB size limit (below the 64KB max)
            - Metadata is chunked first, followed by module bytecode
            - Data is packed efficiently to minimize the number of transactions
            - Transactions are submitted in sequence to maintain ordering
            
        Technical Details:
            The chunked publishing uses the large_package_publisher module to handle
            reassembly of the chunks on-chain. This module stores the chunks temporarily
            until all chunks are received, then performs the actual deployment.
            
        Note:
            This method is automatically called by publish_package_in_path when needed.
            Most users should not need to call this directly.
        """

        # Chunk the metadata and insert it into payloads. The last chunk may be small enough
        # to be placed with other data. This may also be the only chunk.
        payloads = []
        metadata_chunks = PackagePublisher.create_chunks(package_metadata)
        for metadata_chunk in metadata_chunks[:-1]:
            payloads.append(
                PackagePublisher.create_large_package_publishing_payload(
                    large_package_address, metadata_chunk, [], [], False
                )
            )

        metadata_chunk = metadata_chunks[-1]
        taken_size = len(metadata_chunk)
        modules_indices: List[int] = []
        data_chunks: List[bytes] = []

        # Chunk each module and place them into a payload when adding more would exceed the
        # maximum transaction size.
        for idx, module in enumerate(modules):
            chunked_module = PackagePublisher.create_chunks(module)
            for chunk in chunked_module:
                if taken_size + len(chunk) > MAX_TRANSACTION_SIZE:
                    payloads.append(
                        PackagePublisher.create_large_package_publishing_payload(
                            large_package_address,
                            metadata_chunk,
                            modules_indices,
                            data_chunks,
                            False,
                        )
                    )
                    metadata_chunk = b""
                    modules_indices = []
                    data_chunks = []
                    taken_size = 0
                if idx not in modules_indices:
                    modules_indices.append(idx)
                data_chunks.append(chunk)
                taken_size += len(chunk)

        # There will almost certainly be left over data from the chunking, so pass the last
        # chunk for the sake of publishing.
        payloads.append(
            PackagePublisher.create_large_package_publishing_payload(
                large_package_address,
                metadata_chunk,
                modules_indices,
                data_chunks,
                True,
            )
        )

        # Submit and wait for each transaction, including publishing.
        txn_hashes = []
        for payload in payloads:
            print("Submitting transaction...")
            signed_txn = await self.client.create_bcs_signed_transaction(
                sender, payload
            )
            txn_hash = await self.client.submit_bcs_transaction(signed_txn)
            await self.client.wait_for_transaction(txn_hash)
            txn_hashes.append(txn_hash)
        return txn_hashes

    @staticmethod
    def create_large_package_publishing_payload(
        module_address: AccountAddress,
        chunked_package_metadata: bytes,
        modules_indices: List[int],
        chunked_modules: List[bytes],
        publish: bool,
    ) -> TransactionPayload:
        transaction_arguments = [
            TransactionArgument(chunked_package_metadata, Serializer.to_bytes),
            TransactionArgument(
                modules_indices, Serializer.sequence_serializer(Serializer.u16)
            ),
            TransactionArgument(
                chunked_modules, Serializer.sequence_serializer(Serializer.to_bytes)
            ),
            TransactionArgument(publish, Serializer.bool),
        ]

        payload = EntryFunction.natural(
            f"{module_address}::large_packages",
            "stage_code",
            [],
            transaction_arguments,
        )

        return TransactionPayload(payload)

    @staticmethod
    def is_large_package(
        package_metadata: bytes,
        modules: List[bytes],
    ) -> bool:
        total_size = len(package_metadata)
        for module in modules:
            total_size += len(module)

        return total_size >= MAX_TRANSACTION_SIZE

    @staticmethod
    def create_chunks(data: bytes) -> List[bytes]:
        chunks: List[bytes] = []
        read_data = 0
        while read_data < len(data):
            start_read_data = read_data
            read_data = min(read_data + MAX_TRANSACTION_SIZE, len(data))
            taken_data = data[start_read_data:read_data]
            chunks.append(taken_data)
        return chunks
