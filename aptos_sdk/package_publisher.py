# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

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
    """A wrapper around publishing packages."""

    client: RestClient

    def __init__(self, client: RestClient):
        self.client = client

    async def publish_package(
        self, sender: Account, package_metadata: bytes, modules: List[bytes]
    ) -> str:
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
        sequence_number = await self.client.account_sequence_number(publisher_address)
        return self.create_object_deployment_address(
            publisher_address, sequence_number + 1
        )

    @staticmethod
    def create_object_deployment_address(
        creator_address: AccountAddress, creator_sequence_number: int
    ) -> AccountAddress:
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
        """
        Chunks the package_metadata and modules across as many transactions as necessary.
        Each transaction has a base cost and the maximum size is currently 64K, so this chunks
        them into 62K + the base transaction size. This should be sufficient for reasonably
        optimistic transaction batching. The batching tries to place as much data in a transaction
        before moving to the chunk to the next transaction.
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
