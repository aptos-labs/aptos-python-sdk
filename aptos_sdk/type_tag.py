# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Type tag definitions for Move types in the Aptos Python SDK.

This module provides type representations for the Move language type system.
Move is Aptos' smart contract programming language, and this module contains
Python representations of Move's primitive and composite types.

The module includes:
- TypeTag: Root class for all Move type representations
- Primitive type tags for basic Move types (bool, u8, u16, u32, u64, u128, u256, address)
- StructTag: Representation of custom Move structs with generic type parameters
- Serialization/deserialization support for all type tags

Examples:
    Creating and using primitive type tags::

        # Create a u64 type tag
        u64_tag = TypeTag(U64Tag(1234567890))

        # Create a boolean type tag
        bool_tag = TypeTag(BoolTag(True))

    Creating struct type tags::

        # Create a simple struct tag
        struct_tag = StructTag(
            AccountAddress.from_str("0x1"),
            "coin",
            "Coin",
            [TypeTag(U64Tag(0))]  # Generic type parameter
        )

        # Parse from string format
        parsed = StructTag.from_str("0x1::coin::Coin<u64>")

    Serialization::

        # All type tags support BCS serialization
        serialized = struct_tag.to_bytes()
        deserialized = StructTag.from_bytes(serialized)
"""

from __future__ import annotations

import typing
import unittest
from typing import List, Tuple

from .account_address import AccountAddress
from .bcs import Deserializable, Deserializer, Serializable, Serializer


class TypeTag(Deserializable, Serializable):
    """Root class representing Move language types in Aptos.

    TypeTag is a discriminated union that can contain any Move type, including
    primitive types (bool, integers, addresses) and complex types (structs, vectors).
    Each TypeTag wraps a specific type tag implementation and provides a unified
    interface for type operations.

    The discriminator values correspond to Move's type system:

    Attributes:
        BOOL: Discriminator for boolean types (0)
        U8: Discriminator for 8-bit unsigned integers (1)
        U64: Discriminator for 64-bit unsigned integers (2)
        U128: Discriminator for 128-bit unsigned integers (3)
        ACCOUNT_ADDRESS: Discriminator for account addresses (4)
        SIGNER: Discriminator for signer types (5) - not implemented
        VECTOR: Discriminator for vector types (6) - not implemented
        STRUCT: Discriminator for custom struct types (7)
        U16: Discriminator for 16-bit unsigned integers (8)
        U32: Discriminator for 32-bit unsigned integers (9)
        U256: Discriminator for 256-bit unsigned integers (10)
        value: The wrapped type tag implementation

    Examples:
        Creating type tags for primitives::

            bool_type = TypeTag(BoolTag(True))
            u64_type = TypeTag(U64Tag(12345))
            address_type = TypeTag(AccountAddressTag(
                AccountAddress.from_str("0x1")
            ))

        Creating struct type tags::

            struct_type = TypeTag(StructTag(
                AccountAddress.from_str("0x1"),
                "coin", "Coin", []
            ))
    """

    BOOL: int = 0
    U8: int = 1
    U64: int = 2
    U128: int = 3
    ACCOUNT_ADDRESS: int = 4
    SIGNER: int = 5
    VECTOR: int = 6
    STRUCT: int = 7
    U16: int = 8
    U32: int = 9
    U256: int = 10

    value: typing.Any

    def __init__(self, value: typing.Any):
        """Initialize a TypeTag with a specific type implementation.

        Args:
            value: The type tag implementation (e.g., BoolTag, U64Tag, StructTag)
        """
        self.value = value

    def __eq__(self, other: object) -> bool:
        """Check equality with another TypeTag.

        Args:
            other: The object to compare with.

        Returns:
            True if both TypeTags represent the same type and value.
        """
        if not isinstance(other, TypeTag):
            return NotImplemented
        return (
            self.value.variant() == other.value.variant() and self.value == other.value
        )

    def __str__(self):
        """Get string representation of the type tag.

        Returns:
            String representation of the underlying type.
        """
        return self.value.__str__()

    def __repr__(self):
        """Get detailed string representation for debugging.

        Returns:
            String representation of the type tag.
        """
        return self.__str__()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> TypeTag:
        """Deserialize a TypeTag from a BCS byte stream.

        Args:
            deserializer: The BCS deserializer to read from.

        Returns:
            The deserialized TypeTag instance.

        Raises:
            NotImplementedError: If the type variant is not supported
                (SIGNER, VECTOR) or unknown.
        """
        variant = deserializer.uleb128()
        if variant == TypeTag.BOOL:
            return TypeTag(BoolTag.deserialize(deserializer))
        elif variant == TypeTag.U8:
            return TypeTag(U8Tag.deserialize(deserializer))
        elif variant == TypeTag.U16:
            return TypeTag(U16Tag.deserialize(deserializer))
        elif variant == TypeTag.U32:
            return TypeTag(U32Tag.deserialize(deserializer))
        elif variant == TypeTag.U64:
            return TypeTag(U64Tag.deserialize(deserializer))
        elif variant == TypeTag.U128:
            return TypeTag(U128Tag.deserialize(deserializer))
        elif variant == TypeTag.U256:
            return TypeTag(U256Tag.deserialize(deserializer))
        elif variant == TypeTag.ACCOUNT_ADDRESS:
            return TypeTag(AccountAddressTag.deserialize(deserializer))
        elif variant == TypeTag.SIGNER:
            raise NotImplementedError
        elif variant == TypeTag.VECTOR:
            raise NotImplementedError
        elif variant == TypeTag.STRUCT:
            return TypeTag(StructTag.deserialize(deserializer))
        raise NotImplementedError

    def serialize(self, serializer: Serializer):
        """Serialize this TypeTag to a BCS byte stream.

        Args:
            serializer: The BCS serializer to write to.
        """
        serializer.uleb128(self.value.variant())
        serializer.struct(self.value)


class BoolTag(Deserializable, Serializable):
    """Type tag for Move boolean values.

    Represents the Move `bool` primitive type, which can hold true or false values.

    Attributes:
        value: The boolean value this tag represents.

    Examples:
        Creating and using BoolTag::

            true_tag = BoolTag(True)
            false_tag = BoolTag(False)

            # Serialize/deserialize
            serialized = true_tag.to_bytes()
            deserialized = BoolTag.from_bytes(serialized)
    """

    value: bool

    def __init__(self, value: bool):
        """Initialize a BoolTag with a boolean value.

        Args:
            value: The boolean value to wrap.
        """
        self.value = value

    def __eq__(self, other: object) -> bool:
        """Check equality with another BoolTag.

        Args:
            other: The object to compare with.

        Returns:
            True if both tags represent the same boolean value.
        """
        if not isinstance(other, BoolTag):
            return NotImplemented
        return self.value == other.value

    def __str__(self):
        """Get string representation of the boolean value.

        Returns:
            String representation ("True" or "False").
        """
        return self.value.__str__()

    def variant(self):
        """Get the type discriminator for this tag.

        Returns:
            The BOOL type discriminator.
        """
        return TypeTag.BOOL

    @staticmethod
    def deserialize(deserializer: Deserializer) -> BoolTag:
        """Deserialize a BoolTag from a BCS byte stream.

        Args:
            deserializer: The BCS deserializer to read from.

        Returns:
            The deserialized BoolTag instance.
        """
        return BoolTag(deserializer.bool())

    def serialize(self, serializer: Serializer):
        """Serialize this BoolTag to a BCS byte stream.

        Args:
            serializer: The BCS serializer to write to.
        """
        serializer.bool(self.value)


class U8Tag(Deserializable, Serializable):
    """Type tag for Move 8-bit unsigned integer values.

    Represents the Move `u8` primitive type, which holds unsigned 8-bit integers
    in the range 0-255.

    Attributes:
        value: The u8 integer value this tag represents.

    Examples:
        Creating and using U8Tag::

            tag = U8Tag(255)  # Maximum u8 value

            # Serialize/deserialize
            serialized = tag.to_bytes()
            deserialized = U8Tag.from_bytes(serialized)
    """

    value: int

    def __init__(self, value: int):
        """Initialize a U8Tag with an 8-bit unsigned integer.

        Args:
            value: The u8 value to wrap (0-255).
        """
        self.value = value

    def __eq__(self, other: object) -> bool:
        """Check equality with another U8Tag.

        Args:
            other: The object to compare with.

        Returns:
            True if both tags represent the same u8 value.
        """
        if not isinstance(other, U8Tag):
            return NotImplemented
        return self.value == other.value

    def __str__(self):
        """Get string representation of the u8 value.

        Returns:
            String representation of the integer value.
        """
        return self.value.__str__()

    def variant(self):
        """Get the type discriminator for this tag.

        Returns:
            The U8 type discriminator.
        """
        return TypeTag.U8

    @staticmethod
    def deserialize(deserializer: Deserializer) -> U8Tag:
        """Deserialize a U8Tag from a BCS byte stream.

        Args:
            deserializer: The BCS deserializer to read from.

        Returns:
            The deserialized U8Tag instance.
        """
        return U8Tag(deserializer.u8())

    def serialize(self, serializer: Serializer):
        """Serialize this U8Tag to a BCS byte stream.

        Args:
            serializer: The BCS serializer to write to.
        """
        serializer.u8(self.value)


class U16Tag(Deserializable, Serializable):
    """Type tag for Move 16-bit unsigned integer values.

    Represents the Move `u16` primitive type, which holds unsigned 16-bit integers
    in the range 0-65535.

    Attributes:
        value: The u16 integer value this tag represents.
    """

    value: int

    def __init__(self, value: int):
        """Initialize a U16Tag with a 16-bit unsigned integer.

        Args:
            value: The u16 value to wrap (0-65535).
        """
        self.value = value

    def __eq__(self, other: object) -> bool:
        """Check equality with another U16Tag."""
        if not isinstance(other, U16Tag):
            return NotImplemented
        return self.value == other.value

    def __str__(self):
        """Get string representation of the u16 value."""
        return self.value.__str__()

    def variant(self):
        """Get the type discriminator for this tag."""
        return TypeTag.U16

    @staticmethod
    def deserialize(deserializer: Deserializer) -> U16Tag:
        """Deserialize a U16Tag from a BCS byte stream."""
        return U16Tag(deserializer.u16())

    def serialize(self, serializer: Serializer):
        """Serialize this U16Tag to a BCS byte stream."""
        serializer.u16(self.value)


class U32Tag(Deserializable, Serializable):
    """Type tag for Move 32-bit unsigned integer values.

    Represents the Move `u32` primitive type, which holds unsigned 32-bit integers
    in the range 0-4294967295.

    Attributes:
        value: The u32 integer value this tag represents.
    """

    value: int

    def __init__(self, value: int):
        """Initialize a U32Tag with a 32-bit unsigned integer.

        Args:
            value: The u32 value to wrap (0-4294967295).
        """
        self.value = value

    def __eq__(self, other: object) -> bool:
        """Check equality with another U32Tag."""
        if not isinstance(other, U32Tag):
            return NotImplemented
        return self.value == other.value

    def __str__(self):
        """Get string representation of the u32 value."""
        return self.value.__str__()

    def variant(self):
        """Get the type discriminator for this tag."""
        return TypeTag.U32

    @staticmethod
    def deserialize(deserializer: Deserializer) -> U32Tag:
        """Deserialize a U32Tag from a BCS byte stream."""
        return U32Tag(deserializer.u32())

    def serialize(self, serializer: Serializer):
        """Serialize this U32Tag to a BCS byte stream."""
        serializer.u32(self.value)


class U64Tag(Deserializable, Serializable):
    """Type tag for Move 64-bit unsigned integer values.

    Represents the Move `u64` primitive type, which holds unsigned 64-bit integers
    in the range 0-18446744073709551615.

    Attributes:
        value: The u64 integer value this tag represents.
    """

    value: int

    def __init__(self, value: int):
        """Initialize a U64Tag with a 64-bit unsigned integer.

        Args:
            value: The u64 value to wrap (0-18446744073709551615).
        """
        self.value = value

    def __eq__(self, other: object) -> bool:
        """Check equality with another U64Tag."""
        if not isinstance(other, U64Tag):
            return NotImplemented
        return self.value == other.value

    def __str__(self):
        """Get string representation of the u64 value."""
        return self.value.__str__()

    def variant(self):
        """Get the type discriminator for this tag."""
        return TypeTag.U64

    @staticmethod
    def deserialize(deserializer: Deserializer) -> U64Tag:
        """Deserialize a U64Tag from a BCS byte stream."""
        return U64Tag(deserializer.u64())

    def serialize(self, serializer: Serializer):
        """Serialize this U64Tag to a BCS byte stream."""
        serializer.u64(self.value)


class U128Tag(Deserializable, Serializable):
    """Type tag for Move 128-bit unsigned integer values.

    Represents the Move `u128` primitive type, which holds unsigned 128-bit integers
    in the range 0-340282366920938463463374607431768211455.

    Attributes:
        value: The u128 integer value this tag represents.
    """

    value: int

    def __init__(self, value: int):
        """Initialize a U128Tag with a 128-bit unsigned integer.

        Args:
            value: The u128 value to wrap.
        """
        self.value = value

    def __eq__(self, other: object) -> bool:
        """Check equality with another U128Tag."""
        if not isinstance(other, U128Tag):
            return NotImplemented
        return self.value == other.value

    def __str__(self):
        """Get string representation of the u128 value."""
        return self.value.__str__()

    def variant(self):
        """Get the type discriminator for this tag."""
        return TypeTag.U128

    @staticmethod
    def deserialize(deserializer: Deserializer) -> U128Tag:
        """Deserialize a U128Tag from a BCS byte stream."""
        return U128Tag(deserializer.u128())

    def serialize(self, serializer: Serializer):
        """Serialize this U128Tag to a BCS byte stream."""
        serializer.u128(self.value)


class U256Tag(Deserializable, Serializable):
    """Type tag for Move 256-bit unsigned integer values.

    Represents the Move `u256` primitive type, which holds unsigned 256-bit integers.

    Attributes:
        value: The u256 integer value this tag represents.
    """

    value: int

    def __init__(self, value: int):
        """Initialize a U256Tag with a 256-bit unsigned integer.

        Args:
            value: The u256 value to wrap.
        """
        self.value = value

    def __eq__(self, other: object) -> bool:
        """Check equality with another U256Tag."""
        if not isinstance(other, U256Tag):
            return NotImplemented
        return self.value == other.value

    def __str__(self):
        """Get string representation of the u256 value."""
        return self.value.__str__()

    def variant(self):
        """Get the type discriminator for this tag."""
        return TypeTag.U256

    @staticmethod
    def deserialize(deserializer: Deserializer) -> U256Tag:
        """Deserialize a U256Tag from a BCS byte stream."""
        return U256Tag(deserializer.u256())

    def serialize(self, serializer: Serializer):
        """Serialize this U256Tag to a BCS byte stream."""
        serializer.u256(self.value)


class AccountAddressTag(Deserializable, Serializable):
    """Type tag for Move address values.

    Represents the Move `address` primitive type, which holds account addresses
    used to identify accounts and resources on the Aptos blockchain.

    Attributes:
        value: The AccountAddress value this tag represents.

    Examples:
        Creating and using AccountAddressTag::

            addr = AccountAddress.from_str("0x1")
            tag = AccountAddressTag(addr)

            # Serialize/deserialize
            serialized = tag.to_bytes()
            deserialized = AccountAddressTag.from_bytes(serialized)
    """

    value: AccountAddress

    def __init__(self, value: AccountAddress):
        """Initialize an AccountAddressTag with an account address.

        Args:
            value: The AccountAddress to wrap.
        """
        self.value = value

    def __eq__(self, other: object) -> bool:
        """Check equality with another AccountAddressTag."""
        if not isinstance(other, AccountAddressTag):
            return NotImplemented
        return self.value == other.value

    def __str__(self):
        """Get string representation of the address value."""
        return self.value.__str__()

    def variant(self):
        """Get the type discriminator for this tag."""
        return TypeTag.ACCOUNT_ADDRESS

    @staticmethod
    def deserialize(deserializer: Deserializer) -> AccountAddressTag:
        """Deserialize an AccountAddressTag from a BCS byte stream."""
        return AccountAddressTag(deserializer.struct(AccountAddress))

    def serialize(self, serializer: Serializer):
        """Serialize this AccountAddressTag to a BCS byte stream."""
        serializer.struct(self.value)


class StructTag(Deserializable, Serializable):
    """Type tag for Move struct types.

    Represents custom Move struct types, which are user-defined composite types
    that can have generic type parameters. StructTags fully specify a struct
    type including its location (address and module), name, and type arguments.

    Attributes:
        address: The account address where the module is published.
        module: The name of the module containing the struct.
        name: The name of the struct.
        type_args: List of type arguments for generic structs.

    Examples:
        Creating struct tags::

            # Simple struct without generics
            struct_tag = StructTag(
                AccountAddress.from_str("0x1"),
                "account", "Account", []
            )

            # Generic struct with type parameters
            coin_tag = StructTag(
                AccountAddress.from_str("0x1"),
                "coin", "Coin",
                [TypeTag(StructTag(
                    AccountAddress.from_str("0x1"),
                    "aptos_coin", "AptosCoin", []
                ))]
            )

        Parsing from string::

            tag = StructTag.from_str("0x1::coin::Coin<0x1::aptos_coin::AptosCoin>")
            print(tag)  # "0x1::coin::Coin<0x1::aptos_coin::AptosCoin>"
    """

    address: AccountAddress
    module: str
    name: str
    type_args: List[TypeTag]

    def __init__(self, address, module, name, type_args):
        """Initialize a StructTag.

        Args:
            address: The account address where the struct's module is published.
            module: The name of the module containing the struct.
            name: The name of the struct.
            type_args: List of type arguments for generic type parameters.
        """
        self.address = address
        self.module = module
        self.name = name
        self.type_args = type_args

    def __eq__(self, other: object) -> bool:
        """Check equality with another StructTag.

        Args:
            other: The object to compare with.

        Returns:
            True if both StructTags represent the same struct type.
        """
        if not isinstance(other, StructTag):
            return NotImplemented
        return (
            self.address == other.address
            and self.module == other.module
            and self.name == other.name
            and self.type_args == other.type_args
        )

    def __str__(self) -> str:
        """Get the canonical string representation of this struct type.

        The format is: address::module::name<type_arg1, type_arg2, ...>

        Returns:
            String representation of the struct type.
        """
        value = f"{self.address}::{self.module}::{self.name}"
        if len(self.type_args) > 0:
            value += f"<{self.type_args[0]}"
            for type_arg in self.type_args[1:]:
                value += f", {type_arg}"
            value += ">"
        return value

    @staticmethod
    def from_str(type_tag: str) -> StructTag:
        """Parse a StructTag from its string representation.

        Args:
            type_tag: String representation of a struct type, e.g.,
                "0x1::coin::Coin<0x1::aptos_coin::AptosCoin>"

        Returns:
            The parsed StructTag instance.

        Examples:
            Parsing simple and complex struct types::

                simple = StructTag.from_str("0x1::account::Account")

                nested = StructTag.from_str(
                    "0x1::coin::Coin<0x1::aptos_coin::AptosCoin>"
                )
        """
        return StructTag._from_str_internal(type_tag, 0)[0][0].value

    @staticmethod
    def _from_str_internal(type_tag: str, index: int) -> Tuple[List[TypeTag], int]:
        """Internal recursive parser for struct type strings.

        This method handles the complex parsing of nested generic types,
        including proper handling of angle brackets and comma separators.

        Args:
            type_tag: The string to parse.
            index: Current parsing position.

        Returns:
            Tuple of (parsed type tags list, new index position).
        """
        name = ""
        tags = []
        inner_tags: List[TypeTag] = []

        while index < len(type_tag):
            letter = type_tag[index]
            index += 1

            if letter == " ":
                continue

            if letter == "<":
                (inner_tags, index) = StructTag._from_str_internal(type_tag, index)
            elif letter == ",":
                split = name.split("::")
                tag = TypeTag(
                    StructTag(
                        AccountAddress.from_str_relaxed(split[0]),
                        split[1],
                        split[2],
                        inner_tags,
                    )
                )
                tags.append(tag)
                name = ""
                inner_tags = []
            elif letter == ">":
                break
            else:
                name += letter

        split = name.split("::")
        tag = TypeTag(
            StructTag(
                AccountAddress.from_str_relaxed(split[0]),
                split[1],
                split[2],
                inner_tags,
            )
        )
        tags.append(tag)
        return (tags, index)

    def variant(self):
        """Get the type discriminator for this tag.

        Returns:
            The STRUCT type discriminator.
        """
        return TypeTag.STRUCT

    @staticmethod
    def deserialize(deserializer: Deserializer) -> StructTag:
        """Deserialize a StructTag from a BCS byte stream.

        Args:
            deserializer: The BCS deserializer to read from.

        Returns:
            The deserialized StructTag instance.
        """
        address = deserializer.struct(AccountAddress)
        module = deserializer.str()
        name = deserializer.str()
        type_args = deserializer.sequence(TypeTag.deserialize)
        return StructTag(address, module, name, type_args)

    def serialize(self, serializer: Serializer):
        """Serialize this StructTag to a BCS byte stream.

        Args:
            serializer: The BCS serializer to write to.
        """
        self.address.serialize(serializer)
        serializer.str(self.module)
        serializer.str(self.name)
        serializer.sequence(self.type_args, Serializer.struct)


class Test(unittest.TestCase):
    """Test suite for type tag functionality.

    Tests parsing, serialization, and string representation of complex
    nested struct types with multiple levels of generic type parameters.
    """

    def test_nested_structs(self):
        l0 = "0x0::l0::L0"
        l10 = "0x1::l10::L10"
        l20 = "0x2::l20::L20"
        l11 = "0x1::l11::L11"
        composite = f"{l0}<{l10}<{l20}>, {l11}>"
        derived = StructTag.from_str(composite)
        self.assertEqual(composite, f"{derived}")
        in_bytes = derived.to_bytes()
        from_bytes = StructTag.from_bytes(in_bytes)
        self.assertEqual(derived, from_bytes)


if __name__ == "__main__":
    unittest.main()
