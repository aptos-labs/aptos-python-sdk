# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Aptos Token V1 client for legacy NFT and token management.

This module provides client functionality for interacting with the legacy Aptos Token V1 standard,
which was the original NFT implementation on Aptos before the introduction of Token Objects
(the current standard). While Token V1 is still supported for backward compatibility, new
projects should consider using the Token Objects standard via AptosTokenClient.

Legacy Token V1 Features:
- **Collection Creation**: Create named collections with metadata
- **Token Minting**: Create tokens within collections with supply management
- **Transfer Mechanisms**: Both direct transfers and offer/claim workflows
- **Property Management**: Basic token properties and metadata
- **Royalty Support**: Built-in creator royalty system

Key Differences from Token Objects:
- Uses table-based storage instead of object model
- Limited property system compared to modern Token Objects
- More complex transfer mechanisms (offer/claim vs direct transfer)
- Different address derivation for token identification
- Legacy BCS serialization patterns

Token V1 Architecture:
    Token V1 uses a table-based approach where:
    - Collections are stored in creator's Collections resource
    - Tokens are identified by (creator, collection, name, property_version) tuple
    - Token ownership tracked in recipient's TokenStore resource
    - Properties stored as separate key-value mappings

Migration Note:
    For new projects, consider using AptosTokenClient (Token Objects) which provides:
    - Better composability and extensibility
    - Improved property system with type safety
    - Simplified transfer mechanisms
    - Object-based architecture for better on-chain interactions

Examples:
    Basic Token V1 workflow::

        from aptos_sdk.aptos_tokenv1_client import AptosTokenV1Client
        from aptos_sdk.async_client import RestClient
        from aptos_sdk.account import Account

        # Setup
        client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")
        token_client = AptosTokenV1Client(client)
        creator = Account.load("./creator.json")

        # Create a collection
        collection_txn = await token_client.create_collection(
            account=creator,
            name="My Legacy Collection",
            description="A collection using Token V1 standard",
            uri="https://example.com/collection.json"
        )
        await client.wait_for_transaction(collection_txn)

        # Create a token in the collection
        token_txn = await token_client.create_token(
            account=creator,
            collection_name="My Legacy Collection",
            name="Token #1",
            description="First token in legacy format",
            supply=1,  # NFT with supply of 1
            uri="https://example.com/token1.json",
            royalty_points_per_million=50000  # 5% royalty
        )
        await client.wait_for_transaction(token_txn)

    Token transfer using offer/claim pattern::

        from aptos_sdk.account_address import AccountAddress

        recipient_address = AccountAddress.from_str("<recipient...>")
        recipient = Account.load("./recipient.json")

        # Offer token to recipient
        offer_txn = await token_client.offer_token(
            account=creator,
            receiver=recipient_address,
            creator=creator.address(),
            collection_name="My Legacy Collection",
            token_name="Token #1",
            property_version=0,
            amount=1
        )
        await client.wait_for_transaction(offer_txn)

        # Recipient claims the token
        claim_txn = await token_client.claim_token(
            account=recipient,
            sender=creator.address(),
            creator=creator.address(),
            collection_name="My Legacy Collection",
            token_name="Token #1",
            property_version=0
        )
        await client.wait_for_transaction(claim_txn)

    Direct token transfer (requires both accounts)::

        # Direct transfer between accounts
        transfer_txn = await token_client.direct_transfer_token(
            sender=creator,
            receiver=recipient,
            creators_address=creator.address(),
            collection_name="My Legacy Collection",
            token_name="Token #1",
            property_version=0,
            amount=1
        )
        await client.wait_for_transaction(transfer_txn)

    Reading token information::

        # Get token data (metadata)
        token_data = await token_client.get_token_data(
            creator=creator.address(),
            collection_name="My Legacy Collection",
            token_name="Token #1",
            property_version=0
        )
        print(f"Token: {token_data['name']}")
        print(f"Description: {token_data['description']}")
        print(f"Supply: {token_data['supply']}")

        # Get token balance for an account
        balance = await token_client.get_token_balance(
            owner=recipient_address,
            creator=creator.address(),
            collection_name="My Legacy Collection",
            token_name="Token #1",
            property_version=0
        )
        print(f"Balance: {balance}")

        # Get collection information
        collection_data = await token_client.get_collection(
            creator=creator.address(),
            collection_name="My Legacy Collection"
        )
        print(f"Collection: {collection_data['name']}")
        print(f"Max supply: {collection_data['maximum']}")

Limitations of Token V1:
    - Complex token identification system
    - Limited property types and extensibility
    - Table lookups required for token information
    - More gas-intensive operations
    - Less composable than object-based tokens

Security Considerations:
    - Always verify token authenticity by checking creator
    - Be cautious with property_version when transferring
    - Validate collection and token names to prevent spoofing
    - Consider supply limits when minting fungible tokens

Compatibility:
    This client maintains compatibility with existing Token V1 deployments
    and provides migration utilities for upgrading to Token Objects when
    appropriate.

See Also:
    - AptosTokenClient: For new Token Objects standard
    - Token migration guides: For upgrading from V1 to Token Objects
"""

from typing import Any

from .account import Account
from .account_address import AccountAddress
from .async_client import ApiError, RestClient
from .bcs import Serializer
from .transactions import EntryFunction, TransactionArgument, TransactionPayload

U64_MAX = 18446744073709551615


class AptosTokenV1Client:
    """Client for interacting with legacy Aptos Token V1 standard.

    AptosTokenV1Client provides a high-level interface for working with the original
    Aptos token implementation (Token V1). While this standard is still supported
    for backward compatibility, new projects should consider using Token Objects
    via AptosTokenClient for better functionality and composability.

    Token V1 uses a table-based storage model where tokens are identified by
    a combination of (creator, collection_name, token_name, property_version)
    and stored in various on-chain tables rather than as independent objects.

    Key Features:
    - **Legacy Compatibility**: Supports existing Token V1 deployments
    - **Collection Management**: Create and manage token collections
    - **Token Lifecycle**: Create, transfer, and query tokens
    - **Offer/Claim Transfers**: Asynchronous token transfer mechanism
    - **Direct Transfers**: Synchronous multi-agent transfers
    - **Royalty System**: Built-in creator royalty support

    Attributes:
        _client (RestClient): The underlying REST client for blockchain communication.

    Examples:
        Initialize and create a basic NFT::

            from aptos_sdk.aptos_tokenv1_client import AptosTokenV1Client
            from aptos_sdk.async_client import RestClient
            from aptos_sdk.account import Account

            # Setup client
            rest_client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")
            token_client = AptosTokenV1Client(rest_client)
            creator = Account.load("./creator_key.json")

            # Create collection
            await token_client.create_collection(
                account=creator,
                name="Art Collection",
                description="Digital art pieces",
                uri="https://example.com/collection.json"
            )

            # Create NFT
            await token_client.create_token(
                account=creator,
                collection_name="Art Collection",
                name="Artwork #1",
                description="Beautiful digital art",
                supply=1,
                uri="https://example.com/art1.json",
                royalty_points_per_million=25000  # 2.5%
            )

        Transfer tokens using offer/claim::

            # Offer token to recipient
            await token_client.offer_token(
                account=current_owner,
                receiver=recipient_address,
                creator=creator.address(),
                collection_name="Art Collection",
                token_name="Artwork #1",
                property_version=0,
                amount=1
            )

            # Recipient claims the token
            await token_client.claim_token(
                account=recipient,
                sender=current_owner.address(),
                creator=creator.address(),
                collection_name="Art Collection",
                token_name="Artwork #1",
                property_version=0
            )

    Note:
        This client is for Token V1 compatibility. For new projects, consider
        using AptosTokenClient which implements the modern Token Objects standard
        with improved functionality and composability.
    """

    _client: RestClient

    def __init__(self, client: RestClient):
        """Initialize the Token V1 client with a REST client.

        Args:
            client: The RestClient instance to use for blockchain communication.
                Must be configured for the appropriate Aptos network.

        Examples:
            Create client for devnet::

                from aptos_sdk.async_client import RestClient

                rest_client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")
                token_client = AptosTokenV1Client(rest_client)
        """
        self._client = client

    async def create_collection(
        self, account: Account, name: str, description: str, uri: str
    ) -> str:
        """Create a new token collection using the Token V1 standard.

        Creates a collection that can hold multiple tokens. In Token V1,
        collections are stored in the creator's account and have a maximum
        supply limit (set to U64_MAX by default for unlimited).

        Args:
            account: The account that will own the collection and pay transaction fees.
            name: Unique name for the collection within the creator's account.
                Must be unique per creator.
            description: Human-readable description of the collection.
            uri: URI pointing to collection metadata JSON file.

        Returns:
            str: Transaction hash of the collection creation transaction.

        Raises:
            ApiError: If the transaction fails or collection name already exists.

        Examples:
            Create a basic art collection::

                tx_hash = await token_client.create_collection(
                    account=creator,
                    name="Digital Art Collection",
                    description="Unique digital artworks by Artist Name",
                    uri="https://example.com/collection-metadata.json"
                )
                await client.wait_for_transaction(tx_hash)

        Note:
            Collection names must be unique per creator. The collection is created
            with unlimited maximum supply and default mutability settings (all false).
        """

        transaction_arguments = [
            TransactionArgument(name, Serializer.str),
            TransactionArgument(description, Serializer.str),
            TransactionArgument(uri, Serializer.str),
            TransactionArgument(U64_MAX, Serializer.u64),
            TransactionArgument(
                [False, False, False], Serializer.sequence_serializer(Serializer.bool)
            ),
        ]

        payload = EntryFunction.natural(
            "0x3::token",
            "create_collection_script",
            [],
            transaction_arguments,
        )

        signed_transaction = await self._client.create_bcs_signed_transaction(
            account, TransactionPayload(payload)
        )
        return await self._client.submit_bcs_transaction(signed_transaction)

    async def create_token(
        self,
        account: Account,
        collection_name: str,
        name: str,
        description: str,
        supply: int,
        uri: str,
        royalty_points_per_million: int,
    ) -> str:
        """Create a new token within an existing collection.

        Creates a token with the specified supply and metadata. In Token V1,
        tokens have both initial and maximum supply values, with royalties
        specified as points per million (e.g., 25000 = 2.5%).

        Args:
            account: The account creating the token (must be collection owner).
            collection_name: Name of the collection to create token in.
            name: Unique name for the token within the collection.
            description: Human-readable description of the token.
            supply: Initial and maximum supply of the token.
                Use 1 for NFTs, higher values for fungible tokens.
            uri: URI pointing to token metadata JSON file.
            royalty_points_per_million: Royalty percentage as points per million.
                25000 = 2.5%, 50000 = 5%, etc.

        Returns:
            str: Transaction hash of the token creation transaction.

        Raises:
            ApiError: If the transaction fails, collection doesn't exist,
                or token name already exists.

        Examples:
            Create an NFT (supply = 1)::

                tx_hash = await token_client.create_token(
                    account=creator,
                    collection_name="Art Collection",
                    name="Masterpiece #1",
                    description="A unique digital artwork",
                    supply=1,  # NFT
                    uri="https://example.com/token1.json",
                    royalty_points_per_million=25000  # 2.5% royalty
                )

            Create a fungible token::

                tx_hash = await token_client.create_token(
                    account=creator,
                    collection_name="Game Tokens",
                    name="Gold Coins",
                    description="In-game currency",
                    supply=1000000,  # 1M tokens
                    uri="https://example.com/gold-coins.json",
                    royalty_points_per_million=10000  # 1% royalty
                )

        Note:
            Token names must be unique within the collection. The royalty
            recipient is set to the token creator's address by default.
        """
        transaction_arguments = [
            TransactionArgument(collection_name, Serializer.str),
            TransactionArgument(name, Serializer.str),
            TransactionArgument(description, Serializer.str),
            TransactionArgument(supply, Serializer.u64),
            TransactionArgument(supply, Serializer.u64),
            TransactionArgument(uri, Serializer.str),
            TransactionArgument(account.address(), Serializer.struct),
            # SDK assumes per million
            TransactionArgument(1000000, Serializer.u64),
            TransactionArgument(royalty_points_per_million, Serializer.u64),
            TransactionArgument(
                [False, False, False, False, False],
                Serializer.sequence_serializer(Serializer.bool),
            ),
            TransactionArgument([], Serializer.sequence_serializer(Serializer.str)),
            TransactionArgument(
                [], Serializer.sequence_serializer(Serializer.to_bytes)
            ),
            TransactionArgument([], Serializer.sequence_serializer(Serializer.str)),
        ]

        payload = EntryFunction.natural(
            "0x3::token",
            "create_token_script",
            [],
            transaction_arguments,
        )
        signed_transaction = await self._client.create_bcs_signed_transaction(
            account, TransactionPayload(payload)
        )
        return await self._client.submit_bcs_transaction(signed_transaction)

    async def offer_token(
        self,
        account: Account,
        receiver: AccountAddress,
        creator: AccountAddress,
        collection_name: str,
        token_name: str,
        property_version: int,
        amount: int,
    ) -> str:
        """Offer tokens to another account using the async transfer mechanism.

        Creates a pending token offer that the recipient can claim. This is the
        first step of the two-phase Token V1 transfer process (offer -> claim).
        The tokens remain in the sender's account until claimed.

        Args:
            account: The account offering the tokens (current owner).
            receiver: Address of the account to receive the token offer.
            creator: Address of the account that created the token.
            collection_name: Name of the collection containing the token.
            token_name: Name of the specific token being offered.
            property_version: Property version of the token (usually 0).
            amount: Number of tokens to offer.

        Returns:
            str: Transaction hash of the offer transaction.

        Raises:
            ApiError: If the transaction fails, token doesn't exist,
                or insufficient token balance.

        Examples:
            Offer an NFT::

                tx_hash = await token_client.offer_token(
                    account=current_owner,
                    receiver=recipient_address,
                    creator=original_creator.address(),
                    collection_name="Art Collection",
                    token_name="Masterpiece #1",
                    property_version=0,
                    amount=1
                )

            Offer fungible tokens::

                tx_hash = await token_client.offer_token(
                    account=token_holder,
                    receiver=buyer_address,
                    creator=token_creator.address(),
                    collection_name="Game Tokens",
                    token_name="Gold Coins",
                    property_version=0,
                    amount=100
                )

        Note:
            The recipient must call claim_token() to complete the transfer.
            Offers can potentially be revoked or expire based on implementation.
        """
        transaction_arguments = [
            TransactionArgument(receiver, Serializer.struct),
            TransactionArgument(creator, Serializer.struct),
            TransactionArgument(collection_name, Serializer.str),
            TransactionArgument(token_name, Serializer.str),
            TransactionArgument(property_version, Serializer.u64),
            TransactionArgument(amount, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x3::token_transfers",
            "offer_script",
            [],
            transaction_arguments,
        )
        signed_transaction = await self._client.create_bcs_signed_transaction(
            account, TransactionPayload(payload)
        )
        return await self._client.submit_bcs_transaction(signed_transaction)

    async def claim_token(
        self,
        account: Account,
        sender: AccountAddress,
        creator: AccountAddress,
        collection_name: str,
        token_name: str,
        property_version: int,
    ) -> str:
        """Claim tokens that were offered by another account.

        Completes the second step of the Token V1 async transfer process.
        Claims all tokens that were offered for the specified token ID.

        Args:
            account: The account claiming the tokens (recipient).
            sender: Address of the account that offered the tokens.
            creator: Address of the account that created the token.
            collection_name: Name of the collection containing the token.
            token_name: Name of the specific token being claimed.
            property_version: Property version of the token (usually 0).

        Returns:
            str: Transaction hash of the claim transaction.

        Raises:
            ApiError: If the transaction fails or no pending offer exists.

        Examples:
            Claim an offered NFT::

                tx_hash = await token_client.claim_token(
                    account=recipient,
                    sender=previous_owner.address(),
                    creator=original_creator.address(),
                    collection_name="Art Collection",
                    token_name="Masterpiece #1",
                    property_version=0
                )

        Note:
            This claims all tokens that were offered for this token ID.
            The amount is determined by the original offer transaction.
        """
        transaction_arguments = [
            TransactionArgument(sender, Serializer.struct),
            TransactionArgument(creator, Serializer.struct),
            TransactionArgument(collection_name, Serializer.str),
            TransactionArgument(token_name, Serializer.str),
            TransactionArgument(property_version, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x3::token_transfers",
            "claim_script",
            [],
            transaction_arguments,
        )
        signed_transaction = await self._client.create_bcs_signed_transaction(
            account, TransactionPayload(payload)
        )
        return await self._client.submit_bcs_transaction(signed_transaction)

    async def direct_transfer_token(
        self,
        sender: Account,
        receiver: Account,
        creators_address: AccountAddress,
        collection_name: str,
        token_name: str,
        property_version: int,
        amount: int,
    ) -> str:
        """Transfer tokens directly between two accounts in a single transaction.

        Performs a synchronous token transfer that requires both sender and
        receiver to sign the transaction. This is more efficient than the
        offer/claim mechanism but requires coordination between both parties.

        Args:
            sender: The account sending the tokens (must sign).
            receiver: The account receiving the tokens (must sign).
            creators_address: Address of the account that created the token.
            collection_name: Name of the collection containing the token.
            token_name: Name of the specific token being transferred.
            property_version: Property version of the token (usually 0).
            amount: Number of tokens to transfer.

        Returns:
            str: Transaction hash of the direct transfer transaction.

        Raises:
            ApiError: If the transaction fails, token doesn't exist,
                insufficient balance, or either party fails to sign.

        Examples:
            Direct transfer of an NFT::

                tx_hash = await token_client.direct_transfer_token(
                    sender=current_owner,
                    receiver=new_owner,
                    creators_address=creator.address(),
                    collection_name="Art Collection",
                    token_name="Masterpiece #1",
                    property_version=0,
                    amount=1
                )

        Note:
            This creates a multi-agent transaction requiring both accounts
            to sign. Both sender and receiver must be available to sign
            simultaneously.
        """
        transaction_arguments = [
            TransactionArgument(creators_address, Serializer.struct),
            TransactionArgument(collection_name, Serializer.str),
            TransactionArgument(token_name, Serializer.str),
            TransactionArgument(property_version, Serializer.u64),
            TransactionArgument(amount, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x3::token",
            "direct_transfer_script",
            [],
            transaction_arguments,
        )

        signed_transaction = await self._client.create_multi_agent_bcs_transaction(
            sender,
            [receiver],
            TransactionPayload(payload),
        )
        return await self._client.submit_bcs_transaction(signed_transaction)

    #
    # Token accessors
    #

    async def get_token(
        self,
        owner: AccountAddress,
        creator: AccountAddress,
        collection_name: str,
        token_name: str,
        property_version: int,
    ) -> Any:
        """Retrieve token information for a specific owner and token ID.

        Queries the owner's TokenStore to get information about their
        holdings of a specific token, including the amount owned.

        Args:
            owner: Address of the account that owns the token.
            creator: Address of the account that created the token.
            collection_name: Name of the collection containing the token.
            token_name: Name of the specific token.
            property_version: Property version of the token (usually 0).

        Returns:
            Dict containing token information including:
            - 'id': Token identifier object
            - 'amount': String representation of amount owned
            Returns {'id': token_id, 'amount': '0'} if not found.

        Raises:
            ApiError: If the query fails (except for 404 not found).

        Examples:
            Get token ownership info::

                token_info = await token_client.get_token(
                    owner=holder_address,
                    creator=creator.address(),
                    collection_name="Art Collection",
                    token_name="Masterpiece #1",
                    property_version=0
                )

                amount = token_info['amount']
                if amount == '0':
                    print("Account does not own this token")
                else:
                    print(f"Account owns {amount} of this token")

        Note:
            Returns amount as '0' if the account has no TokenStore resource
            or doesn't own the specified token.
        """
        resource = await self._client.account_resource(owner, "0x3::token::TokenStore")
        token_store_handle = resource["data"]["tokens"]["handle"]

        token_id = {
            "token_data_id": {
                "creator": str(creator),
                "collection": collection_name,
                "name": token_name,
            },
            "property_version": str(property_version),
        }

        try:
            return await self._client.get_table_item(
                token_store_handle,
                "0x3::token::TokenId",
                "0x3::token::Token",
                token_id,
            )
        except ApiError as e:
            if e.status_code == 404:
                return {
                    "id": token_id,
                    "amount": "0",
                }
            raise

    async def get_token_balance(
        self,
        owner: AccountAddress,
        creator: AccountAddress,
        collection_name: str,
        token_name: str,
        property_version: int,
    ) -> str:
        """Get the token balance for a specific owner and token ID.

        Convenience method that extracts just the amount from get_token().
        Returns the number of tokens of the specified type owned by the account.

        Args:
            owner: Address of the account to check balance for.
            creator: Address of the account that created the token.
            collection_name: Name of the collection containing the token.
            token_name: Name of the specific token.
            property_version: Property version of the token (usually 0).

        Returns:
            str: String representation of the token balance.
                Returns '0' if the account doesn't own any of this token.

        Examples:
            Check NFT ownership::

                balance = await token_client.get_token_balance(
                    owner=user_address,
                    creator=creator.address(),
                    collection_name="Art Collection",
                    token_name="Masterpiece #1",
                    property_version=0
                )

                owns_nft = balance != '0'
                print(f"User owns NFT: {owns_nft}")

            Check fungible token balance::

                balance = await token_client.get_token_balance(
                    owner=player_address,
                    creator=game_creator.address(),
                    collection_name="Game Tokens",
                    token_name="Gold Coins",
                    property_version=0
                )

                print(f"Player has {balance} gold coins")
        """
        info = await self.get_token(
            owner, creator, collection_name, token_name, property_version
        )
        return info["amount"]

    async def get_token_data(
        self,
        creator: AccountAddress,
        collection_name: str,
        token_name: str,
        property_version: int,
    ) -> Any:
        """Retrieve metadata and configuration for a specific token.

        Queries the token creator's Collections resource to get the
        canonical token data including metadata, supply, and properties.

        Args:
            creator: Address of the account that created the token.
            collection_name: Name of the collection containing the token.
            token_name: Name of the specific token.
            property_version: Property version of the token (usually 0).

        Returns:
            Dict containing token metadata including:
            - 'name': Token name
            - 'description': Token description
            - 'uri': Metadata URI
            - 'supply': Current supply
            - 'maximum': Maximum supply
            - 'royalty': Royalty information
            - Other token-specific fields

        Raises:
            ApiError: If the token doesn't exist or query fails.

        Examples:
            Get token metadata::

                token_data = await token_client.get_token_data(
                    creator=creator.address(),
                    collection_name="Art Collection",
                    token_name="Masterpiece #1",
                    property_version=0
                )

                print(f"Token: {token_data['name']}")
                print(f"Description: {token_data['description']}")
                print(f"URI: {token_data['uri']}")
                print(f"Supply: {token_data['supply']}/{token_data['maximum']}")

        Note:
            This returns the canonical token definition, not ownership
            information. Use get_token() to check specific ownership.
        """
        resource = await self._client.account_resource(
            creator, "0x3::token::Collections"
        )
        token_data_handle = resource["data"]["token_data"]["handle"]

        token_data_id = {
            "creator": str(creator),
            "collection": collection_name,
            "name": token_name,
        }

        return await self._client.get_table_item(
            token_data_handle,
            "0x3::token::TokenDataId",
            "0x3::token::TokenData",
            token_data_id,
        )  # <:!:read_token_data_table

    async def get_collection(
        self, creator: AccountAddress, collection_name: str
    ) -> Any:
        """Retrieve metadata and configuration for a specific collection.

        Queries the collection creator's Collections resource to get
        collection metadata and configuration settings.

        Args:
            creator: Address of the account that created the collection.
            collection_name: Name of the collection to query.

        Returns:
            Dict containing collection information including:
            - 'name': Collection name
            - 'description': Collection description
            - 'uri': Collection metadata URI
            - 'maximum': Maximum number of tokens allowed
            - 'supply': Current number of tokens created
            - Mutability settings for various fields

        Raises:
            ApiError: If the collection doesn't exist or query fails.

        Examples:
            Get collection info::

                collection_data = await token_client.get_collection(
                    creator=creator.address(),
                    collection_name="Art Collection"
                )

                print(f"Collection: {collection_data['name']}")
                print(f"Description: {collection_data['description']}")
                print(f"URI: {collection_data['uri']}")
                print(f"Supply: {collection_data['supply']}/{collection_data['maximum']}")

        Note:
            This provides collection-level metadata. Use get_token_data()
            to get information about specific tokens within the collection.
        """
        resource = await self._client.account_resource(
            creator, "0x3::token::Collections"
        )
        token_data = resource["data"]["collection_data"]["handle"]

        return await self._client.get_table_item(
            token_data,
            "0x1::string::String",
            "0x3::token::CollectionData",
            collection_name,
        )

    async def transfer_object(
        self, owner: Account, object: AccountAddress, to: AccountAddress
    ) -> str:
        """Transfer an object-based resource to another account.

        This method is for transferring object-based resources and may be
        used for hybrid Token V1/Object scenarios. Not typically used for
        standard Token V1 transfers.

        Args:
            owner: The current owner of the object.
            object: Address of the object to transfer.
            to: Address of the account to receive the object.

        Returns:
            str: Transaction hash of the transfer transaction.

        Raises:
            ApiError: If the transaction fails or object doesn't exist.

        Note:
            This method is primarily for object-based transfers and may not
            be applicable to standard Token V1 tokens. Use direct_transfer_token
            or the offer/claim pattern for regular Token V1 transfers.
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

        signed_transaction = await self._client.create_bcs_signed_transaction(
            owner,
            TransactionPayload(payload),
        )
        return await self._client.submit_bcs_transaction(signed_transaction)
