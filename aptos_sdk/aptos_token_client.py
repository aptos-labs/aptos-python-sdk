# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Aptos Token (Digital Assets) client for NFT and digital asset management.

This module provides comprehensive tools for creating, managing, and interacting with
digital assets (also known as Token Objects or NFTs) on the Aptos blockchain. It supports
the latest Aptos token standard which is built on the object model for better flexibility
and composability.

Key Features:
- **Collection Management**: Create and manage NFT collections with configurable properties
- **Token Minting**: Mint regular and soul-bound tokens with custom properties
- **Token Operations**: Transfer, burn, freeze/unfreeze tokens
- **Property Management**: Add, remove, and update token properties dynamically
- **Royalty Support**: Built-in royalty mechanisms for creators
- **Object Model**: Leverages Aptos' object model for improved token architecture

Digital Asset Architecture:
    The Aptos token standard uses the object model where each token is represented
    as an independent object on-chain. This provides several benefits:

    - **Composability**: Tokens can be extended with additional resources
    - **Flexibility**: Properties can be modified after creation (if permitted)
    - **Efficiency**: Direct object addressing without complex lookups
    - **Interoperability**: Standard interface for all digital assets

Token Lifecycle:
    1. **Collection Creation**: Create a collection to hold related tokens
    2. **Token Minting**: Mint individual tokens within the collection
    3. **Property Management**: Add, update, or remove token properties
    4. **Transfer/Trade**: Transfer ownership between accounts
    5. **Lifecycle Management**: Freeze, unfreeze, or burn tokens as needed

Collection Features:
    - **Mutable Metadata**: Configure which aspects can be changed after creation
    - **Supply Management**: Set maximum supply limits
    - **Creator Controls**: Configure burn and freeze permissions
    - **Royalty System**: Built-in royalty distribution for secondary sales

Property System:
    Tokens support rich property systems with typed values:
    - **Basic Types**: bool, u8, u16, u32, u64, u128, u256
    - **Complex Types**: address, string, byte vectors
    - **Dynamic Updates**: Properties can be modified post-creation (if allowed)
    - **Type Safety**: Property values are strongly typed and serialized safely

Examples:
    Create a basic NFT collection and mint tokens::

        from aptos_sdk.aptos_token_client import AptosTokenClient, PropertyMap, Property
        from aptos_sdk.async_client import RestClient
        from aptos_sdk.account import Account

        # Setup
        client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")
        token_client = AptosTokenClient(client)
        creator = Account.load("./creator_account.json")

        # Create collection
        collection_txn = await token_client.create_collection(
            creator=creator,
            description="My amazing NFT collection",
            max_supply=1000,
            name="Amazing NFTs",
            uri="https://example.com/collection.json",
            mutable_description=True,
            mutable_royalty=False,
            mutable_uri=True,
            mutable_token_description=True,
            mutable_token_name=False,
            mutable_token_properties=True,
            mutable_token_uri=True,
            tokens_burnable_by_creator=True,
            tokens_freezable_by_creator=False,
            royalty_numerator=5,    # 5% royalty
            royalty_denominator=100
        )

        await client.wait_for_transaction(collection_txn)
        print(f"Collection created: {collection_txn}")

    Mint a token with custom properties::

        # Create properties for the token
        properties = PropertyMap([
            Property.string("rarity", "legendary"),
            Property.u64("level", 42),
            Property.bool("is_special", True),
            Property.bytes("metadata", b"custom_data")
        ])

        # Mint the token
        mint_txn = await token_client.mint_token(
            creator=creator,
            collection="Amazing NFTs",
            description="A legendary item with special powers",
            name="Legendary Sword #1",
            uri="https://example.com/tokens/sword1.json",
            properties=properties
        )

        await client.wait_for_transaction(mint_txn)

        # Get the minted token addresses
        token_addresses = await token_client.tokens_minted_from_transaction(mint_txn)
        print(f"Minted token at: {token_addresses[0]}")

    Create a soul-bound token (non-transferable)::

        from aptos_sdk.account_address import AccountAddress

        # Soul-bound tokens cannot be transferred
        recipient = AccountAddress.from_str("0x4abc123...")

        soul_bound_txn = await token_client.mint_soul_bound_token(
            creator=creator,
            collection="Amazing NFTs",
            description="Achievement badge for completing quest",
            name="Quest Master Badge",
            uri="https://example.com/badges/quest_master.json",
            properties=PropertyMap([Property.string("achievement", "quest_master")]),
            soul_bound_to=recipient
        )

    Read token information::

        # Read token details from blockchain
        token_address = AccountAddress.from_str("0x4token_address...")
        token_data = await token_client.read_object(token_address)

        print(f"Token data: {token_data}")

        # Access specific resources
        if Token in token_data.resources:
            token = token_data.resources[Token]
            print(f"Token name: {token.name}")
            print(f"Description: {token.description}")

        if PropertyMap in token_data.resources:
            props = token_data.resources[PropertyMap]
            print(f"Properties: {props}")

    Transfer and manage tokens::

        from aptos_sdk.account_address import AccountAddress

        # Transfer token to another account
        recipient = AccountAddress.from_str("0x4recipient_address...")
        owner = Account.load("./token_owner.json")

        transfer_txn = await token_client.transfer_token(
            owner=owner,
            token=token_addresses[0],
            to=recipient
        )

        # Freeze token (prevent transfers)
        freeze_txn = await token_client.freeze_token(
            creator=creator,
            token=token_addresses[0]
        )

        # Update token properties (if allowed)
        new_property = Property.u64("level", 50)  # Level up!
        update_txn = await token_client.update_token_property(
            creator=creator,
            token=token_addresses[0],
            prop=new_property
        )

Gas Considerations:
    - Collection creation: ~200,000 gas units
    - Token minting: ~150,000 gas units
    - Property updates: ~50,000 gas units
    - Transfers: ~20,000 gas units

Security Best Practices:
    - **Mutable Permissions**: Carefully configure what aspects can be changed
    - **Royalty Settings**: Set reasonable royalty percentages (typically 2.5-10%)
    - **Property Validation**: Validate property values before setting
    - **Creator Controls**: Use burn and freeze permissions judiciously
    - **Testing**: Test collection and token creation on devnet first

Common Use Cases:
    - **Art NFTs**: Digital art with metadata and provenance
    - **Gaming Assets**: In-game items with stats and properties
    - **Certificates**: Soul-bound tokens for achievements and credentials
    - **Collectibles**: Trading cards, sports memorabilia, etc.
    - **Utility Tokens**: Access passes, membership tokens
    - **Music/Media**: Audio, video, and multimedia NFTs

Error Handling:
    Common errors and solutions:
    - **Insufficient Permissions**: Ensure creator has rights to modify tokens
    - **Collection Not Found**: Verify collection name matches exactly
    - **Property Type Mismatch**: Ensure property types are compatible
    - **Transfer Restrictions**: Check if token is frozen or soul-bound
    - **Supply Limits**: Verify collection hasn't reached max supply

Note:
    This implementation uses the latest Aptos token standard (Token Objects)
    which is different from the legacy Token v1 standard. For Token v1 support,
    use the AptosTokenV1Client instead.
"""

from __future__ import annotations

from typing import Any, List, Tuple

from .account import Account
from .account_address import AccountAddress
from .async_client import RestClient
from .bcs import Deserializer, Serializer
from .transactions import EntryFunction, TransactionArgument, TransactionPayload
from .type_tag import StructTag, TypeTag


class Object:
    """Represents an Aptos object with ownership and transfer permissions.

    The Object class encapsulates the core object metadata including ownership
    and transfer restrictions. This is the base resource for all objects on
    Aptos, including digital assets (tokens).

    Attributes:
        allow_ungated_transfer (bool): Whether the object can be transferred
            without explicit permission from the owner.
        owner (AccountAddress): The current owner of the object.
        struct_tag (str): The Move struct identifier for object resources.

    Examples:
        Parse object data from blockchain response::

            resource_data = {
                "allow_ungated_transfer": True,
                "owner": "0x4abc123..."
            }
            obj = Object.parse(resource_data)
            print(f"Object owner: {obj.owner}")
            print(f"Transferable: {obj.allow_ungated_transfer}")

    Note:
        Objects with allow_ungated_transfer=False require explicit approval
        from the owner or authorized parties for transfers.
    """

    allow_ungated_transfer: bool
    owner: AccountAddress

    struct_tag: str = "0x1::object::ObjectCore"

    def __init__(self, allow_ungated_transfer, owner):
        self.allow_ungated_transfer = allow_ungated_transfer
        self.owner = owner

    @staticmethod
    def parse(resource: dict[str, Any]) -> Object:
        """
        Parse an Object from a resource dictionary.

        :param resource: Resource data from the blockchain
        :return: Parsed Object instance
        """
        return Object(
            resource["allow_ungated_transfer"],
            AccountAddress.from_str_relaxed(resource["owner"]),
        )

    def __str__(self) -> str:
        return f"Object[allow_ungated_transfer: {self.allow_ungated_transfer}, owner: {self.owner}]"


class Collection:
    """Represents a token collection on the Aptos blockchain.

    A collection is a container for related tokens (NFTs) that share common
    properties and governance. Collections define the rules and metadata
    for all tokens within them.

    Attributes:
        creator (AccountAddress): The address of the account that created the collection.
        description (str): Human-readable description of the collection.
        name (str): Unique name of the collection.
        uri (str): URI pointing to collection metadata (JSON).
        struct_tag (str): The Move struct identifier for collection resources.

    Examples:
        Parse collection data from blockchain::

            resource_data = {
                "creator": "0x4abc123...",
                "description": "A collection of unique digital art pieces",
                "name": "Art Collection",
                "uri": "https://example.com/collection.json"
            }
            collection = Collection.parse(resource_data)
            print(f"Collection: {collection.name} by {collection.creator}")

    Note:
        The collection URI should point to a JSON file following the standard
        collection metadata schema for proper marketplace compatibility.
    """

    creator: AccountAddress
    description: str
    name: str
    uri: str

    struct_tag: str = "0x4::collection::Collection"

    def __init__(self, creator, description, name, uri):
        self.creator = creator
        self.description = description
        self.name = name
        self.uri = uri

    def __str__(self) -> str:
        return f"AccountAddress[creator: {self.creator}, description: {self.description}, name: {self.name}, ur: {self.uri}]"

    @staticmethod
    def parse(resource: dict[str, Any]) -> Collection:
        """
        Parse a Collection from a resource dictionary.

        :param resource: Resource data from the blockchain
        :return: Parsed Collection instance
        """
        return Collection(
            AccountAddress.from_str_relaxed(resource["creator"]),
            resource["description"],
            resource["name"],
            resource["uri"],
        )


class Royalty:
    """Represents royalty information for token collections and secondary sales.

    Royalties enable creators to earn a percentage of secondary sales of their
    tokens on marketplaces and other platforms. The royalty is represented as
    a fraction (numerator/denominator) and paid to a specific address.

    Attributes:
        numerator (int): The numerator of the royalty fraction.
        denominator (int): The denominator of the royalty fraction.
        payee_address (AccountAddress): The address that receives royalty payments.
        struct_tag (str): The Move struct identifier for royalty resources.

    Examples:
        Calculate royalty percentage::

            royalty = Royalty(250, 10000, payee_address)  # 2.5% royalty
            percentage = (royalty.numerator / royalty.denominator) * 100
            print(f"Royalty: {percentage}% to {royalty.payee_address}")

        Parse royalty from blockchain data::

            resource_data = {
                "numerator": 500,
                "denominator": 10000,
                "payee_address": "0x4abc123..."
            }
            royalty = Royalty.parse(resource_data)
            print(f"Royalty: {royalty}")  # 5% royalty

    Note:
        Common royalty percentages range from 2.5% to 10%. The fraction should
        be simplified to avoid unnecessary precision (e.g., use 1/40 instead of 25/1000).
    """

    numerator: int
    denominator: int
    payee_address: AccountAddress

    struct_tag: str = "0x4::royalty::Royalty"

    def __init__(self, numerator, denominator, payee_address):
        self.numerator = numerator
        self.denominator = denominator
        self.payee_address = payee_address

    def __str__(self) -> str:
        return f"Royalty[numerator: {self.numerator}, denominator: {self.denominator}, payee_address: {self.payee_address}]"

    @staticmethod
    def parse(resource: dict[str, Any]) -> Royalty:
        """
        Parse a Royalty from a resource dictionary.

        :param resource: Resource data from the blockchain
        :return: Parsed Royalty instance
        """
        return Royalty(
            resource["numerator"],
            resource["denominator"],
            AccountAddress.from_str_relaxed(resource["payee_address"]),
        )


class Token:
    """Represents an individual token (NFT) on the Aptos blockchain.

    A token is a unique digital asset within a collection. Each token has
    its own metadata, properties, and can be individually owned and transferred.

    Attributes:
        collection (AccountAddress): Address of the collection this token belongs to.
        index (int): Unique index of the token within its collection.
        description (str): Human-readable description of the token.
        name (str): Name of the token.
        uri (str): URI pointing to token metadata (typically JSON).
        struct_tag (str): The Move struct identifier for token resources.

    Examples:
        Parse token data from blockchain::

            resource_data = {
                "collection": {"inner": "0x4collection_address..."},
                "index": 42,
                "description": "A legendary sword with special powers",
                "name": "Legendary Sword #42",
                "uri": "https://example.com/tokens/42.json"
            }
            token = Token.parse(resource_data)
            print(f"Token: {token.name} in collection {token.collection}")

    Note:
        The token URI should point to a JSON file following the standard
        token metadata schema (similar to ERC-721 metadata) for marketplace
        compatibility.
    """

    collection: AccountAddress
    index: int
    description: str
    name: str
    uri: str

    struct_tag: str = "0x4::token::Token"

    def __init__(
        self,
        collection: AccountAddress,
        index: int,
        description: str,
        name: str,
        uri: str,
    ):
        self.collection = collection
        self.index = index
        self.description = description
        self.name = name
        self.uri = uri

    def __str__(self) -> str:
        return f"Token[collection: {self.collection}, index: {self.index}, description: {self.description}, name: {self.name}, uri: {self.uri}]"

    @staticmethod
    def parse(resource: dict[str, Any]):
        """
        Parse a Token from a resource dictionary.

        :param resource: Resource data from the blockchain
        :return: Parsed Token instance
        """
        return Token(
            AccountAddress.from_str_relaxed(resource["collection"]["inner"]),
            int(resource["index"]),
            resource["description"],
            resource["name"],
            resource["uri"],
        )


class InvalidPropertyType(Exception):
    """Invalid property type"""

    property_type: Any

    def __init__(self, property_type: Any):
        message = f"Unknown property type: {property_type}"
        super().__init__(message)
        self.property_type = property_type


class Property:
    """Represents a typed property for tokens with serialization capabilities.

    Properties are key-value pairs that can be attached to tokens to store
    additional metadata and attributes. Each property has a name, type, and
    value, and supports various primitive and complex types.

    Attributes:
        name (str): The name/key of the property.
        property_type (str): The Move type of the property value.
        value (Any): The actual value of the property.

    Type Constants:
        BOOL (int): Boolean type identifier (0)
        U8 (int): 8-bit unsigned integer type identifier (1)
        U16 (int): 16-bit unsigned integer type identifier (2)
        U32 (int): 32-bit unsigned integer type identifier (3)
        U64 (int): 64-bit unsigned integer type identifier (4)
        U128 (int): 128-bit unsigned integer type identifier (5)
        U256 (int): 256-bit unsigned integer type identifier (6)
        ADDRESS (int): Account address type identifier (7)
        BYTE_VECTOR (int): Byte vector type identifier (8)
        STRING (int): String type identifier (9)

    Examples:
        Create different types of properties::

            # Boolean property
            is_rare = Property.bool("is_rare", True)

            # Numeric properties
            level = Property.u64("level", 25)
            damage = Property.u32("damage", 150)

            # String property
            category = Property.string("category", "weapon")

            # Address property
            creator = Property("creator", "address", creator_address)

            # Byte data property
            metadata = Property.bytes("metadata", b"custom_data")

        Use in transactions::

            # Convert to transaction arguments for on-chain calls
            tx_args = property.to_transaction_arguments()

        Parse from blockchain data::

            # Parse property from resource data
            prop = Property.parse("level", Property.U64, serialized_value)
            print(f"Property: {prop.name} = {prop.value}")

    Supported Types:
        - **bool**: Boolean values (true/false)
        - **u8, u16, u32, u64, u128, u256**: Unsigned integers of various sizes
        - **address**: Aptos account addresses
        - **string**: UTF-8 encoded strings
        - **vector<u8>**: Arbitrary byte arrays

    Note:
        Properties are strongly typed and values must match the specified type.
        BCS serialization is used for efficient on-chain storage and transmission.
    """

    name: str
    property_type: str
    value: Any

    BOOL: int = 0
    U8: int = 1
    U16: int = 2
    U32: int = 3
    U64: int = 4
    U128: int = 5
    U256: int = 6
    ADDRESS: int = 7
    BYTE_VECTOR: int = 8
    STRING: int = 9

    def __init__(self, name: str, property_type: str, value: Any):
        self.name = name
        self.property_type = property_type
        self.value = value

    def __str__(self) -> str:
        return f"Property[{self.name}, {self.property_type}, {self.value}]"

    def serialize_value(self) -> bytes:
        ser = Serializer()
        if self.property_type == "bool":
            Serializer.bool(ser, self.value)
        elif self.property_type == "u8":
            Serializer.u8(ser, self.value)
        elif self.property_type == "u16":
            Serializer.u16(ser, self.value)
        elif self.property_type == "u32":
            Serializer.u32(ser, self.value)
        elif self.property_type == "u64":
            Serializer.u64(ser, self.value)
        elif self.property_type == "u128":
            Serializer.u128(ser, self.value)
        elif self.property_type == "u256":
            Serializer.u256(ser, self.value)
        elif self.property_type == "address":
            Serializer.struct(ser, self.value)
        elif self.property_type == "0x1::string::String":
            Serializer.str(ser, self.value)
        elif self.property_type == "vector<u8>":
            Serializer.to_bytes(ser, self.value)
        else:
            raise InvalidPropertyType(self.property_type)
        return ser.output()

    def to_transaction_arguments(self) -> List[TransactionArgument]:
        return [
            TransactionArgument(self.name, Serializer.str),
            TransactionArgument(self.property_type, Serializer.str),
            TransactionArgument(self.serialize_value(), Serializer.to_bytes),
        ]

    @staticmethod
    def parse(name: str, property_type: int, value: bytes) -> Property:
        deserializer = Deserializer(value)

        if property_type == Property.BOOL:
            return Property(name, "bool", deserializer.bool())
        elif property_type == Property.U8:
            return Property(name, "u8", deserializer.u8())
        elif property_type == Property.U16:
            return Property(name, "u16", deserializer.u16())
        elif property_type == Property.U32:
            return Property(name, "u32", deserializer.u32())
        elif property_type == Property.U64:
            return Property(name, "u64", deserializer.u64())
        elif property_type == Property.U128:
            return Property(name, "u128", deserializer.u128())
        elif property_type == Property.U256:
            return Property(name, "u256", deserializer.u256())
        elif property_type == Property.ADDRESS:
            return Property(name, "address", AccountAddress.deserialize(deserializer))
        elif property_type == Property.STRING:
            return Property(name, "0x1::string::String", deserializer.str())
        elif property_type == Property.BYTE_VECTOR:
            return Property(name, "vector<u8>", deserializer.to_bytes())
        raise InvalidPropertyType(property_type)

    @staticmethod
    def bool(name: str, value: bool) -> Property:
        return Property(name, "bool", value)

    @staticmethod
    def u8(name: str, value: int) -> Property:
        return Property(name, "u8", value)

    @staticmethod
    def u16(name: str, value: int) -> Property:
        return Property(name, "u16", value)

    @staticmethod
    def u32(name: str, value: int) -> Property:
        return Property(name, "u32", value)

    @staticmethod
    def u64(name: str, value: int) -> Property:
        return Property(name, "u64", value)

    @staticmethod
    def u128(name: str, value: int) -> Property:
        return Property(name, "u128", value)

    @staticmethod
    def u256(name: str, value: int) -> Property:
        return Property(name, "u256", value)

    @staticmethod
    def string(name: str, value: str) -> Property:
        return Property(name, "0x1::string::String", value)

    @staticmethod
    def bytes(name: str, value: bytes) -> Property:
        return Property(name, "vector<u8>", value)


class PropertyMap:
    """Container for multiple token properties with serialization support.

    PropertyMap manages a collection of Property objects and provides utilities
    for converting them to formats suitable for blockchain transactions and
    parsing them from on-chain data.

    Attributes:
        properties (List[Property]): List of properties contained in this map.
        struct_tag (str): The Move struct identifier for property map resources.

    Examples:
        Create a property map with various property types::

            properties = PropertyMap([
                Property.string("name", "Legendary Sword"),
                Property.u64("level", 50),
                Property.bool("is_rare", True),
                Property.bytes("metadata", b"custom_data"),
                Property.u32("damage", 200)
            ])

            print(f"Property map: {properties}")

        Convert to transaction format::

            # Get tuple format for transaction arguments
            names, types, values = properties.to_tuple()

            # These can be used directly in transaction calls
            # names = ["name", "level", "is_rare", "metadata", "damage"]
            # types = ["0x1::string::String", "u64", "bool", "vector<u8>", "u32"]
            # values = [b"...", b"...", b"...", b"...", b"..."]  # BCS serialized

        Parse from blockchain data::

            # Parse from resource data retrieved from blockchain
            resource_data = {
                "inner": {
                    "data": [
                        {"key": "level", "value": {"type": 4, "value": "0x464..."}},
                        {"key": "rarity", "value": {"type": 9, "value": "0x4legendary"}}
                    ]
                }
            }

            parsed_map = PropertyMap.parse(resource_data)
            print(f"Parsed properties: {parsed_map}")

    Usage in Token Operations:
        Property maps are essential for token minting and property management::

            # Create property map
            props = PropertyMap([
                Property.string("category", "weapon"),
                Property.u64("attack_power", 150)
            ])

            # Use in token minting
            await token_client.mint_token(
                creator=creator,
                collection="Game Items",
                description="A powerful weapon",
                name="Magic Sword",
                uri="https://example.com/sword.json",
                properties=props
            )

    Note:
        The to_tuple method returns data in the format expected by Move entry
        functions for property operations on tokens.
    """

    properties: List[Property]

    struct_tag: str = "0x4::property_map::PropertyMap"

    def __init__(self, properties: List[Property]):
        self.properties = properties

    def __str__(self) -> str:
        response = "PropertyMap["
        for prop in self.properties:
            response += f"{prop}, "
        if len(self.properties) > 0:
            response = response[:-2]
        response += "]"
        return response

    def to_tuple(self) -> Tuple[List[str], List[str], List[bytes]]:
        names = []
        types = []
        values = []

        for prop in self.properties:
            names.append(prop.name)
            types.append(prop.property_type)
            values.append(prop.serialize_value())

        return (names, types, values)

    @staticmethod
    def parse(resource: dict[str, Any]) -> PropertyMap:
        props = resource["inner"]["data"]
        properties = []
        for prop in props:
            properties.append(
                Property.parse(
                    prop["key"],
                    prop["value"]["type"],
                    bytes.fromhex(prop["value"]["value"][2:]),
                )
            )

        return PropertyMap(properties)


class ReadObject:
    """Aggregated view of parsed blockchain resources for token objects.

    ReadObject provides a structured interface for accessing multiple resource
    types associated with a token object address. It automatically parses
    known resource types and makes them available through a unified interface.

    Attributes:
        resource_map (dict): Mapping of Move struct identifiers to Python classes
            for automatic resource parsing.
        resources (dict): Dictionary mapping resource classes to parsed instances.

    Supported Resource Types:
        - **Collection**: Collection metadata and configuration
        - **Object**: Core object ownership and transfer permissions
        - **PropertyMap**: Token properties and custom attributes
        - **Royalty**: Royalty information for secondary sales
        - **Token**: Token metadata and collection reference

    Examples:
        Read and parse token object resources::

            from aptos_sdk.account_address import AccountAddress

            # Read object from blockchain
            token_address = AccountAddress.from_str("0x4token_address...")
            read_object = await token_client.read_object(token_address)

            # Access different resource types
            if Token in read_object.resources:
                token = read_object.resources[Token]
                print(f"Token name: {token.name}")
                print(f"Description: {token.description}")
                print(f"Collection: {token.collection}")

            if PropertyMap in read_object.resources:
                properties = read_object.resources[PropertyMap]
                print(f"Properties: {properties}")
                for prop in properties.properties:
                    print(f"  {prop.name}: {prop.value}")

            if Object in read_object.resources:
                obj = read_object.resources[Object]
                print(f"Owner: {obj.owner}")
                print(f"Transferable: {obj.allow_ungated_transfer}")

            if Royalty in read_object.resources:
                royalty = read_object.resources[Royalty]
                percentage = (royalty.numerator / royalty.denominator) * 100
                print(f"Royalty: {percentage}% to {royalty.payee_address}")

        Check for specific resource types::

            # Check what resources are available
            print(f"Available resources: {list(read_object.resources.keys())}")

            # Safely access optional resources
            token = read_object.resources.get(Token)
            if token:
                print(f"Found token: {token.name}")
            else:
                print("No token resource found")

        Full object inspection::

            # Print all resources (uses __str__ method)
            print(read_object)

            # This will show something like:
            # ReadObject
            #     0x4::token::Token: Token[collection: 0x4abc..., name: Sword #1, ...]
            #     0x4::property_map::PropertyMap: PropertyMap[Property[level, u64, 42], ...]
            #     0x1::object::ObjectCore: Object[allow_ungated_transfer: True, owner: 0x4def...]

    Usage Patterns:
        Conditional resource access::

            def analyze_token_object(read_object: ReadObject):
                analysis = {}

                # Basic token info
                if Token in read_object.resources:
                    token = read_object.resources[Token]
                    analysis["name"] = token.name
                    analysis["description"] = token.description

                # Properties analysis
                if PropertyMap in read_object.resources:
                    prop_map = read_object.resources[PropertyMap]
                    analysis["property_count"] = len(prop_map.properties)
                    analysis["properties"] = {p.name: p.value for p in prop_map.properties}

                # Ownership info
                if Object in read_object.resources:
                    obj = read_object.resources[Object]
                    analysis["owner"] = str(obj.owner)
                    analysis["transferable"] = obj.allow_ungated_transfer

                return analysis

    Note:
        Only resources that match known struct tags in resource_map will be
        parsed and included. Unknown resource types are ignored during parsing.
    """

    resource_map: dict[str, Any] = {
        Collection.struct_tag: Collection,
        Object.struct_tag: Object,
        PropertyMap.struct_tag: PropertyMap,
        Royalty.struct_tag: Royalty,
        Token.struct_tag: Token,
    }

    resources: dict[Any, Any]

    def __init__(self, resources: dict[Any, Any]):
        self.resources = resources

    def __str__(self) -> str:
        response = "ReadObject"
        for resource_obj, value in self.resources.items():
            response += f"\n\t{resource_obj.struct_tag}: {value}"

        return response


class AptosTokenClient:
    """A wrapper around reading and mutating Digital Assets also known as Token Objects"""

    client: RestClient

    def __init__(self, client: RestClient):
        self.client = client

    async def read_object(self, address: AccountAddress) -> ReadObject:
        """
        Read an object from the blockchain and parse its resources.

        :param address: The address of the object to read
        :return: ReadObject containing parsed resources
        """
        resources = {}

        read_resources = await self.client.account_resources(address)
        for resource in read_resources:
            if resource["type"] in ReadObject.resource_map:
                resource_obj = ReadObject.resource_map[resource["type"]]
                resources[resource_obj] = resource_obj.parse(resource["data"])
        return ReadObject(resources)

    @staticmethod
    def create_collection_payload(
        description: str,
        max_supply: int,
        name: str,
        uri: str,
        mutable_description: bool,
        mutable_royalty: bool,
        mutable_uri: bool,
        mutable_token_description: bool,
        mutable_token_name: bool,
        mutable_token_properties: bool,
        mutable_token_uri: bool,
        tokens_burnable_by_creator: bool,
        tokens_freezable_by_creator: bool,
        royalty_numerator: int,
        royalty_denominator: int,
    ) -> TransactionPayload:
        """
        Create a transaction payload for creating a new token collection.

        :param description: Description of the collection
        :param max_supply: Maximum number of tokens that can be minted in this collection
        :param name: Name of the collection
        :param uri: URI for collection metadata
        :param mutable_description: Whether the collection description can be changed
        :param mutable_royalty: Whether the collection royalty can be changed
        :param mutable_uri: Whether the collection URI can be changed
        :param mutable_token_description: Whether token descriptions can be changed
        :param mutable_token_name: Whether token names can be changed
        :param mutable_token_properties: Whether token properties can be changed
        :param mutable_token_uri: Whether token URIs can be changed
        :param tokens_burnable_by_creator: Whether tokens can be burned by the creator
        :param tokens_freezable_by_creator: Whether tokens can be frozen by the creator
        :param royalty_numerator: Numerator for royalty percentage calculation
        :param royalty_denominator: Denominator for royalty percentage calculation
        :return: Transaction payload for collection creation
        """
        transaction_arguments = [
            TransactionArgument(description, Serializer.str),
            TransactionArgument(max_supply, Serializer.u64),
            TransactionArgument(name, Serializer.str),
            TransactionArgument(uri, Serializer.str),
            TransactionArgument(mutable_description, Serializer.bool),
            TransactionArgument(mutable_royalty, Serializer.bool),
            TransactionArgument(mutable_uri, Serializer.bool),
            TransactionArgument(mutable_token_description, Serializer.bool),
            TransactionArgument(mutable_token_name, Serializer.bool),
            TransactionArgument(mutable_token_properties, Serializer.bool),
            TransactionArgument(mutable_token_uri, Serializer.bool),
            TransactionArgument(tokens_burnable_by_creator, Serializer.bool),
            TransactionArgument(tokens_freezable_by_creator, Serializer.bool),
            TransactionArgument(royalty_numerator, Serializer.u64),
            TransactionArgument(royalty_denominator, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x4::aptos_token",
            "create_collection",
            [],
            transaction_arguments,
        )

        return TransactionPayload(payload)

    # :!:>create_collection
    async def create_collection(
        self,
        creator: Account,
        description: str,
        max_supply: int,
        name: str,
        uri: str,
        mutable_description: bool,
        mutable_royalty: bool,
        mutable_uri: bool,
        mutable_token_description: bool,
        mutable_token_name: bool,
        mutable_token_properties: bool,
        mutable_token_uri: bool,
        tokens_burnable_by_creator: bool,
        tokens_freezable_by_creator: bool,
        royalty_numerator: int,
        royalty_denominator: int,
    ) -> str:  # <:!:create_collection
        """
        Create a new token collection on the blockchain.

        :param creator: The account that will create and own the collection
        :param description: Description of the collection
        :param max_supply: Maximum number of tokens that can be minted in this collection
        :param name: Name of the collection
        :param uri: URI for collection metadata
        :param mutable_description: Whether the collection description can be changed
        :param mutable_royalty: Whether the collection royalty can be changed
        :param mutable_uri: Whether the collection URI can be changed
        :param mutable_token_description: Whether token descriptions can be changed
        :param mutable_token_name: Whether token names can be changed
        :param mutable_token_properties: Whether token properties can be changed
        :param mutable_token_uri: Whether token URIs can be changed
        :param tokens_burnable_by_creator: Whether tokens can be burned by the creator
        :param tokens_freezable_by_creator: Whether tokens can be frozen by the creator
        :param royalty_numerator: Numerator for royalty percentage calculation
        :param royalty_denominator: Denominator for royalty percentage calculation
        :return: Transaction hash as a hex string
        :raises ApiError: If transaction submission fails
        """
        payload = AptosTokenClient.create_collection_payload(
            description,
            max_supply,
            name,
            uri,
            mutable_description,
            mutable_royalty,
            mutable_uri,
            mutable_token_description,
            mutable_token_name,
            mutable_token_properties,
            mutable_token_uri,
            tokens_burnable_by_creator,
            tokens_freezable_by_creator,
            royalty_numerator,
            royalty_denominator,
        )
        signed_transaction = await self.client.create_bcs_signed_transaction(
            creator, payload
        )
        return await self.client.submit_bcs_transaction(signed_transaction)

    @staticmethod
    def mint_token_payload(
        collection: str,
        description: str,
        name: str,
        uri: str,
        properties: PropertyMap,
    ) -> TransactionPayload:
        """
        Create a transaction payload for minting a new token.

        :param collection: Name of the collection to mint the token in
        :param description: Description of the token
        :param name: Name of the token
        :param uri: URI for token metadata
        :param properties: PropertyMap containing token properties
        :return: Transaction payload for token minting
        """
        (property_names, property_types, property_values) = properties.to_tuple()
        transaction_arguments = [
            TransactionArgument(collection, Serializer.str),
            TransactionArgument(description, Serializer.str),
            TransactionArgument(name, Serializer.str),
            TransactionArgument(uri, Serializer.str),
            TransactionArgument(
                property_names, Serializer.sequence_serializer(Serializer.str)
            ),
            TransactionArgument(
                property_types, Serializer.sequence_serializer(Serializer.str)
            ),
            TransactionArgument(
                property_values, Serializer.sequence_serializer(Serializer.to_bytes)
            ),
        ]

        payload = EntryFunction.natural(
            "0x4::aptos_token",
            "mint",
            [],
            transaction_arguments,
        )

        return TransactionPayload(payload)

    # :!:>mint_token
    async def mint_token(
        self,
        creator: Account,
        collection: str,
        description: str,
        name: str,
        uri: str,
        properties: PropertyMap,
    ) -> str:  # <:!:mint_token
        """
        Mint a new token in the specified collection.

        :param creator: The account that will mint the token
        :param collection: Name of the collection to mint the token in
        :param description: Description of the token
        :param name: Name of the token
        :param uri: URI for token metadata
        :param properties: PropertyMap containing token properties
        :return: Transaction hash as a hex string
        :raises ApiError: If transaction submission fails
        """
        payload = AptosTokenClient.mint_token_payload(
            collection, description, name, uri, properties
        )
        signed_transaction = await self.client.create_bcs_signed_transaction(
            creator, payload
        )
        return await self.client.submit_bcs_transaction(signed_transaction)

    async def mint_soul_bound_token(
        self,
        creator: Account,
        collection: str,
        description: str,
        name: str,
        uri: str,
        properties: PropertyMap,
        soul_bound_to: AccountAddress,
    ) -> str:
        """
        Mint a new soul-bound token that cannot be transferred.

        :param creator: The account that will mint the token
        :param collection: Name of the collection to mint the token in
        :param description: Description of the token
        :param name: Name of the token
        :param uri: URI for token metadata
        :param properties: PropertyMap containing token properties
        :param soul_bound_to: Address of the account the token will be soul-bound to
        :return: Transaction hash as a hex string
        :raises ApiError: If transaction submission fails
        """
        (property_names, property_types, property_values) = properties.to_tuple()
        transaction_arguments = [
            TransactionArgument(collection, Serializer.str),
            TransactionArgument(description, Serializer.str),
            TransactionArgument(name, Serializer.str),
            TransactionArgument(uri, Serializer.str),
            TransactionArgument(
                property_names, Serializer.sequence_serializer(Serializer.str)
            ),
            TransactionArgument(
                property_types, Serializer.sequence_serializer(Serializer.str)
            ),
            TransactionArgument(
                property_values, Serializer.sequence_serializer(Serializer.to_bytes)
            ),
            TransactionArgument(soul_bound_to, Serializer.struct),
        ]

        payload = EntryFunction.natural(
            "0x4::aptos_token",
            "mint_soul_bound",
            [],
            transaction_arguments,
        )

        signed_transaction = await self.client.create_bcs_signed_transaction(
            creator, TransactionPayload(payload)
        )
        return await self.client.submit_bcs_transaction(signed_transaction)

    # :!:>transfer_token
    async def transfer_token(
        self, owner: Account, token: AccountAddress, to: AccountAddress
    ) -> str:
        """
        Transfer ownership of a token to another account.

        :param owner: The current owner of the token
        :param token: The address of the token to transfer
        :param to: The address of the new owner
        :return: Transaction hash as a hex string
        :raises ApiError: If transaction submission fails
        """
        return await self.client.transfer_object(owner, token, to)  # <:!:transfer_token

    async def burn_token(self, creator: Account, token: AccountAddress) -> str:
        """
        Burn (permanently destroy) a token.

        :param creator: The creator account that has permission to burn the token
        :param token: The address of the token to burn
        :return: Transaction hash as a hex string
        :raises ApiError: If transaction submission fails
        """
        payload = EntryFunction.natural(
            "0x4::aptos_token",
            "burn",
            [TypeTag(StructTag.from_str("0x4::token::Token"))],
            [TransactionArgument(token, Serializer.struct)],
        )

        signed_transaction = await self.client.create_bcs_signed_transaction(
            creator, TransactionPayload(payload)
        )
        return await self.client.submit_bcs_transaction(signed_transaction)

    async def freeze_token(self, creator: Account, token: AccountAddress) -> str:
        """
        Freeze a token, preventing its transfer.

        :param creator: The creator account that has permission to freeze the token
        :param token: The address of the token to freeze
        :return: Transaction hash as a hex string
        :raises ApiError: If transaction submission fails
        """
        payload = EntryFunction.natural(
            "0x4::aptos_token",
            "freeze_transfer",
            [TypeTag(StructTag.from_str("0x4::token::Token"))],
            [TransactionArgument(token, Serializer.struct)],
        )

        signed_transaction = await self.client.create_bcs_signed_transaction(
            creator, TransactionPayload(payload)
        )
        return await self.client.submit_bcs_transaction(signed_transaction)

    async def unfreeze_token(self, creator: Account, token: AccountAddress) -> str:
        """
        Unfreeze a previously frozen token, allowing transfers again.

        :param creator: The creator account that has permission to unfreeze the token
        :param token: The address of the token to unfreeze
        :return: Transaction hash as a hex string
        :raises ApiError: If transaction submission fails
        """
        payload = EntryFunction.natural(
            "0x4::aptos_token",
            "unfreeze_transfer",
            [TypeTag(StructTag.from_str("0x4::token::Token"))],
            [TransactionArgument(token, Serializer.struct)],
        )

        signed_transaction = await self.client.create_bcs_signed_transaction(
            creator, TransactionPayload(payload)
        )
        return await self.client.submit_bcs_transaction(signed_transaction)

    async def add_token_property(
        self, creator: Account, token: AccountAddress, prop: Property
    ) -> str:
        """
        Add a new property to an existing token.

        :param creator: The creator account that has permission to modify the token
        :param token: The address of the token to modify
        :param prop: The property to add to the token
        :return: Transaction hash as a hex string
        :raises ApiError: If transaction submission fails
        """
        transaction_arguments = [TransactionArgument(token, Serializer.struct)]
        transaction_arguments.extend(prop.to_transaction_arguments())

        payload = EntryFunction.natural(
            "0x4::aptos_token",
            "add_property",
            [TypeTag(StructTag.from_str("0x4::token::Token"))],
            transaction_arguments,
        )

        signed_transaction = await self.client.create_bcs_signed_transaction(
            creator, TransactionPayload(payload)
        )
        return await self.client.submit_bcs_transaction(signed_transaction)

    async def remove_token_property(
        self, creator: Account, token: AccountAddress, name: str
    ) -> str:
        """
        Remove a property from an existing token.

        :param creator: The creator account that has permission to modify the token
        :param token: The address of the token to modify
        :param name: The name of the property to remove
        :return: Transaction hash as a hex string
        :raises ApiError: If transaction submission fails
        """
        transaction_arguments = [
            TransactionArgument(token, Serializer.struct),
            TransactionArgument(name, Serializer.str),
        ]

        payload = EntryFunction.natural(
            "0x4::aptos_token",
            "remove_property",
            [TypeTag(StructTag.from_str("0x4::token::Token"))],
            transaction_arguments,
        )

        signed_transaction = await self.client.create_bcs_signed_transaction(
            creator, TransactionPayload(payload)
        )
        return await self.client.submit_bcs_transaction(signed_transaction)

    async def update_token_property(
        self, creator: Account, token: AccountAddress, prop: Property
    ) -> str:
        """
        Update an existing property on a token.

        :param creator: The creator account that has permission to modify the token
        :param token: The address of the token to modify
        :param prop: The property with updated values
        :return: Transaction hash as a hex string
        :raises ApiError: If transaction submission fails
        """
        transaction_arguments = [TransactionArgument(token, Serializer.struct)]
        transaction_arguments.extend(prop.to_transaction_arguments())

        payload = EntryFunction.natural(
            "0x4::aptos_token",
            "update_property",
            [TypeTag(StructTag.from_str("0x4::token::Token"))],
            transaction_arguments,
        )

        signed_transaction = await self.client.create_bcs_signed_transaction(
            creator, TransactionPayload(payload)
        )
        return await self.client.submit_bcs_transaction(signed_transaction)

    async def tokens_minted_from_transaction(
        self, txn_hash: str
    ) -> List[AccountAddress]:
        """
        Get a list of token addresses that were minted in a specific transaction.

        :param txn_hash: The transaction hash to analyze for minted tokens
        :return: List of addresses of tokens that were minted in the transaction
        :raises ApiError: If transaction lookup fails
        """
        output = await self.client.transaction_by_hash(txn_hash)
        mints = []
        for event in output["events"]:
            if event["type"] not in (
                "0x4::collection::MintEvent",
                "0x4::collection::Mint",
            ):
                continue
            mints.append(AccountAddress.from_str_relaxed(event["data"]["token"]))
        return mints
